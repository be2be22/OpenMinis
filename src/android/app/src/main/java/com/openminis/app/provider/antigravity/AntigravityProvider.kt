package com.openminis.app.provider.antigravity

import com.openminis.app.data.model.AgentToolDefinition
import com.openminis.app.data.model.LLMError
import com.openminis.app.data.model.LLMMessage
import com.openminis.app.data.model.LLMModel
import com.openminis.app.data.model.LLMResponse
import com.openminis.app.data.model.LLMStreamChunk
import com.openminis.app.data.model.LLMUsage
import com.openminis.app.data.model.ThinkingLevel
import com.openminis.app.provider.LLMProvider
import com.openminis.app.provider.gemini.GeminiProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Antigravity (Cloud Code Assist) chat provider.
 *
 * The inner request body is the same Gemini body that [GeminiProvider] builds,
 * including tool declarations and tool-result replay. It is wrapped in the
 * Antigravity envelope by [AntigravityProtocol]. The bearer token comes from
 * [tokenProvider], which refreshes it when needed.
 *
 * @param projectProvider returns the discovered Cloud project id. Blank means
 *   discovery has not run yet, and the request fails with a clear error.
 */
class AntigravityProvider(
    private val tokenProvider: suspend () -> String,
    private val projectProvider: () -> String?,
    private val baseURL: String = AntigravityProtocol.BASE_URLS[0],
    override var model: LLMModel = LLMModel.gemini25Flash,
    private val sessionId: String = UUID.randomUUID().toString(),
) : LLMProvider {

    override val name = "Antigravity"

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.MINUTES)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    override suspend fun sendMessageClamped(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
        thinkingLevel: ThinkingLevel,
    ): LLMResponse = withContext(Dispatchers.IO) {
        val body = envelope(messages, systemPrompt, maxTokens, temperature, imageParts, tools, thinkingLevel)
        val request = buildRequest(stream = false, body = body)
        client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) throw mapHttpError(response.code, text)
            val chunk = AntigravityProtocol.parseChunk(JSONObject(text))
            LLMResponse(
                text = chunk.text,
                stopReason = AntigravityProtocol.mapFinishReason(chunk.finishReason) ?: "end_turn",
                usage = chunk.usage?.toLLMUsage(),
            )
        }
    }

    override fun streamMessageClamped(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
        thinkingLevel: ThinkingLevel,
    ): Flow<LLMStreamChunk> = flow {
        val body = envelope(messages, systemPrompt, maxTokens, temperature, imageParts, tools, thinkingLevel)
        val request = buildRequest(stream = true, body = body)
        val response = client.newCall(request).execute()
        response.use { res ->
            if (!res.isSuccessful) throw mapHttpError(res.code, res.body?.string().orEmpty())
            emit(LLMStreamChunk.Started)
            val reader = BufferedReader(InputStreamReader(res.body!!.byteStream(), Charsets.UTF_8))
            var finish: String? = null
            var toolIndex = 0
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                currentCoroutineContext().ensureActive()
                val event = AntigravityProtocol.parseSseLine(line!!) ?: continue
                val chunk = AntigravityProtocol.parseChunk(event)
                if (chunk.text.isNotEmpty()) emit(LLMStreamChunk.Text(chunk.text))
                for (call in chunk.functionCalls) {
                    val id = "antigravity-call-${toolIndex++}"
                    emit(LLMStreamChunk.ToolUseStart(id, call.name))
                    emit(LLMStreamChunk.ToolCallComplete(id, call.name, call.args, call.thoughtSignature))
                }
                chunk.usage?.let { emit(LLMStreamChunk.Usage(it.toLLMUsage())) }
                chunk.finishReason?.let { finish = it }
            }
            emit(LLMStreamChunk.Finished(AntigravityProtocol.mapFinishReason(finish) ?: "end_turn"))
        }
    }.flowOn(Dispatchers.IO)

    private suspend fun envelope(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
        thinkingLevel: ThinkingLevel,
    ): JSONObject {
        val project = projectProvider()?.takeIf { it.isNotBlank() }
            ?: throw LLMError.ProviderError(
                "Antigravity project is not set up yet. Sign in again to load your project.",
            )
        // Built per call so a model switch is reflected in the inner body.
        val inner = GeminiProvider(apiKey = "", model = model).buildRequestBody(
            messages, systemPrompt, maxTokens, temperature, imageParts, tools, thinkingLevel,
        )
        return AntigravityProtocol.wrapEnvelope(
            model = model.id,
            project = project,
            sessionId = sessionId,
            requestId = "agent-${UUID.randomUUID()}",
            inner = inner,
        )
    }

    private suspend fun buildRequest(stream: Boolean, body: JSONObject): Request {
        val token = tokenProvider()
        val url = "${baseURL.trimEnd('/')}/${AntigravityProtocol.methodPath(stream)}"
        return Request.Builder()
            .url(url)
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .header("Authorization", "Bearer $token")
            .header("User-Agent", AntigravityProtocol.USER_AGENT)
            .header("X-Client-Name", AntigravityProtocol.CLIENT_NAME)
            .header("Accept", if (stream) "text/event-stream" else "application/json")
            .build()
    }

    private fun mapHttpError(status: Int, body: String): LLMError {
        val failure = AntigravityProtocol.classifyHttpError(status, body)
        return when (failure.kind) {
            AntigravityProtocol.ErrorKind.AUTH_REJECTED,
            AntigravityProtocol.ErrorKind.FORBIDDEN -> LLMError.InvalidApiKey(failure.message)
            AntigravityProtocol.ErrorKind.RATE_LIMITED -> LLMError.RateLimited()
            AntigravityProtocol.ErrorKind.SERVER -> LLMError.TransientError(failure.message, httpStatus = status)
            else -> LLMError.ProviderError(failure.message, httpStatus = status)
        }
    }

    private fun AntigravityProtocol.Usage.toLLMUsage(): LLMUsage = LLMUsage(
        inputTokens = promptTokens,
        outputTokens = candidateTokens + thoughtTokens,
        cacheReadInputTokens = cachedTokens.takeIf { it > 0 },
        latestContextTokens = promptTokens,
    )
}
