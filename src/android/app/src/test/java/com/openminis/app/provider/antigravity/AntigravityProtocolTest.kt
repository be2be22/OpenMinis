package com.openminis.app.provider.antigravity

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AntigravityProtocolTest {

    @Test
    fun `envelope wraps the inner request and carries session and project`() {
        val inner = JSONObject().put("contents", org.json.JSONArray())
        val envelope = AntigravityProtocol.wrapEnvelope(
            model = "gemini-3-pro",
            project = "my-project",
            sessionId = "session-1",
            requestId = "agent-123",
            inner = inner,
        )

        assertEquals("gemini-3-pro", envelope.getString("model"))
        assertEquals("antigravity", envelope.getString("userAgent"))
        assertEquals("agent", envelope.getString("requestType"))
        assertEquals("my-project", envelope.getString("project"))
        assertEquals("agent-123", envelope.getString("requestId"))
        assertEquals("session-1", envelope.getJSONObject("request").getString("sessionId"))
    }

    @Test
    fun `method path differs for streaming and non-streaming`() {
        assertEquals("v1internal:generateContent", AntigravityProtocol.methodPath(stream = false))
        assertEquals(
            "v1internal:streamGenerateContent?alt=sse",
            AntigravityProtocol.methodPath(stream = true),
        )
    }

    @Test
    fun `parses text and function calls and unwraps the response envelope`() {
        val json = JSONObject(
            """
            {"response": {
              "candidates": [{
                "content": {"parts": [
                  {"text": "Hello "},
                  {"text": "world"},
                  {"functionCall": {"name": "read_file", "args": {"path": "a.txt"}},
                   "thoughtSignature": "sig-1"}
                ]},
                "finishReason": "STOP"
              }],
              "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 4,
                                "thoughtsTokenCount": 2, "cachedContentTokenCount": 3},
              "modelVersion": "gemini-3-pro"
            }}
            """.trimIndent(),
        )

        val chunk = AntigravityProtocol.parseChunk(json)

        assertEquals("Hello world", chunk.text)
        assertEquals(1, chunk.functionCalls.size)
        assertEquals("read_file", chunk.functionCalls[0].name)
        assertEquals("a.txt", chunk.functionCalls[0].args.getString("path"))
        assertEquals("sig-1", chunk.functionCalls[0].thoughtSignature)
        assertEquals("STOP", chunk.finishReason)
        assertEquals("end_turn", AntigravityProtocol.mapFinishReason(chunk.finishReason))
        assertEquals(10, chunk.usage!!.promptTokens)
        assertEquals(4, chunk.usage!!.candidateTokens)
        assertEquals(2, chunk.usage!!.thoughtTokens)
        assertEquals(3, chunk.usage!!.cachedTokens)
        assertEquals("gemini-3-pro", chunk.modelVersion)
    }

    @Test
    fun `reasoning parts are not shown as answer text`() {
        val json = JSONObject(
            """
            {"candidates": [{"content": {"parts": [
              {"text": "internal plan", "thought": true},
              {"text": "answer"}
            ]}}]}
            """.trimIndent(),
        )

        assertEquals("answer", AntigravityProtocol.parseChunk(json).text)
    }

    @Test
    fun `empty or missing candidates yield an empty chunk`() {
        val chunk = AntigravityProtocol.parseChunk(JSONObject("{}"))

        assertEquals("", chunk.text)
        assertTrue(chunk.functionCalls.isEmpty())
        assertNull(chunk.finishReason)
        assertNull(chunk.usage)
    }

    @Test
    fun `max tokens maps to max_tokens and unknown reasons are lowercased`() {
        assertEquals("max_tokens", AntigravityProtocol.mapFinishReason("MAX_TOKENS"))
        assertEquals("safety", AntigravityProtocol.mapFinishReason("SAFETY"))
        assertNull(AntigravityProtocol.mapFinishReason(null))
    }

    @Test
    fun `sse parser keeps data events and skips comments, done and malformed lines`() {
        assertEquals(
            "x",
            AntigravityProtocol.parseSseLine("data: {\"response\":{\"x\":\"x\"}}")!!
                .getJSONObject("response").getString("x"),
        )
        assertNull(AntigravityProtocol.parseSseLine(": keep-alive"))
        assertNull(AntigravityProtocol.parseSseLine(""))
        assertNull(AntigravityProtocol.parseSseLine("data: [DONE]"))
        assertNull(AntigravityProtocol.parseSseLine("data: {not json"))
    }

    @Test
    fun `http 401 means sign in again and does not expose the body`() {
        val failure = AntigravityProtocol.classifyHttpError(401, """{"error":{"message":"token x"}}""")

        assertEquals(AntigravityProtocol.ErrorKind.AUTH_REJECTED, failure.kind)
        assertFalse(failure.message.contains("token x"))
        assertTrue(failure.message.contains("Sign in again"))
    }

    @Test
    fun `http 403 keeps the short service message`() {
        val failure = AntigravityProtocol.classifyHttpError(
            403,
            """{"error":{"message":"Cloud Code is not enabled for this account"}}""",
        )

        assertEquals(AntigravityProtocol.ErrorKind.FORBIDDEN, failure.kind)
        assertTrue(failure.message.contains("Cloud Code is not enabled"))
    }

    @Test
    fun `rate limit and server errors are classified separately`() {
        assertEquals(
            AntigravityProtocol.ErrorKind.RATE_LIMITED,
            AntigravityProtocol.classifyHttpError(429, "").kind,
        )
        assertEquals(
            AntigravityProtocol.ErrorKind.SERVER,
            AntigravityProtocol.classifyHttpError(503, "").kind,
        )
        assertEquals(
            AntigravityProtocol.ErrorKind.CLIENT,
            AntigravityProtocol.classifyHttpError(400, "not json").kind,
        )
    }

    @Test
    fun `error messages never contain raw status codes`() {
        val messages = listOf(401, 403, 429, 500, 400, 418).map {
            AntigravityProtocol.classifyHttpError(it, "").message
        }
        messages.forEach { assertFalse(it, it.contains("HTTP")) }
    }

    @Test
    fun `base urls keep the iOS probe order`() {
        assertEquals("https://daily-cloudcode-pa.sandbox.googleapis.com", AntigravityProtocol.BASE_URLS[0])
        assertEquals("https://cloudcode-pa.googleapis.com", AntigravityProtocol.BASE_URLS[1])
    }
}
