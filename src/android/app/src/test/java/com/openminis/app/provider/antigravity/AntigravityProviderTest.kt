package com.openminis.app.provider.antigravity

import com.openminis.app.data.model.LLMError
import com.openminis.app.data.model.LLMStreamChunk
import com.openminis.app.data.model.ThinkingLevel
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class AntigravityProviderTest {
    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun provider(project: String? = "proj-1") = AntigravityProvider(
        tokenProvider = { "tok-abc" },
        projectProvider = { project },
        baseURL = server.url("/").toString(),
        sessionId = "session-1",
    )

    private fun send(p: AntigravityProvider) = runBlocking {
        p.sendMessageClamped(emptyList(), null, 256, null, emptyList(), emptyList(), ThinkingLevel.OFF)
    }

    private fun failureOf(status: Int, body: String = "{}"): Throwable {
        server.enqueue(MockResponse().setResponseCode(status).setBody(body))
        try {
            send(provider())
        } catch (e: Throwable) {
            return e
        }
        fail("expected a failure for status $status")
        throw IllegalStateException("unreachable")
    }

    @Test
    fun nonStreamingRequestSendsBearerTokenAndAntigravityEnvelope() {
        server.enqueue(
            MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]},\"finishReason\":\"STOP\"}]}}"),
        )

        val response = send(provider())

        assertEquals("hi", response.text)
        assertEquals("end_turn", response.stopReason)
        val request = server.takeRequest()
        assertEquals("/v1internal:generateContent", request.path)
        assertEquals("Bearer tok-abc", request.getHeader("Authorization"))
        val body = JSONObject(request.body.readUtf8())
        assertEquals("proj-1", body.getString("project"))
        assertEquals("antigravity", body.getString("userAgent"))
        assertEquals("agent", body.getString("requestType"))
        assertEquals("session-1", body.getJSONObject("request").getString("sessionId"))
    }

    @Test
    fun unauthorizedAndForbiddenMapToInvalidCredential() {
        assertTrue(failureOf(401) is LLMError.InvalidApiKey)
        assertTrue(failureOf(403) is LLMError.InvalidApiKey)
    }

    @Test
    fun rateLimitMapsToRateLimitedAndServerErrorToTransient() {
        assertTrue(failureOf(429) is LLMError.RateLimited)
        assertTrue(failureOf(503) is LLMError.TransientError)
    }

    @Test
    fun missingProjectFailsBeforeAnyNetworkCall() {
        try {
            send(provider(project = null))
            fail("expected a provider error")
        } catch (_: LLMError.ProviderError) {
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun streamEmitsTextToolCallUsageAndFinishInOrder() {
        val sse =
            "data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hel\"}]}}]}}\n\n" +
                "data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[" +
                "{\"functionCall\":{\"name\":\"read_file\",\"args\":{\"path\":\"a.txt\"}},\"thoughtSignature\":\"sig\"}" +
                "]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":2}}}\n\n"
        server.enqueue(MockResponse().setHeader("Content-Type", "text/event-stream").setBody(sse))

        val chunks = runBlocking {
            provider().streamMessageClamped(emptyList(), null, 256, null, emptyList(), emptyList(), ThinkingLevel.OFF).toList()
        }

        assertTrue(chunks.first() is LLMStreamChunk.Started)
        assertEquals("Hel", chunks.filterIsInstance<LLMStreamChunk.Text>().single().text)
        val call = chunks.filterIsInstance<LLMStreamChunk.ToolCallComplete>().single()
        assertEquals("read_file", call.name)
        assertEquals("a.txt", call.args.getString("path"))
        assertEquals("sig", call.thoughtSignature)
        assertTrue(chunks.any { it is LLMStreamChunk.Usage })
        assertEquals("end_turn", (chunks.last() as LLMStreamChunk.Finished).stopReason)
    }
}
