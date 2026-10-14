package com.openminis.app.provider.antigravity

import org.json.JSONException
import org.json.JSONObject

/**
 * Pure protocol layer for Antigravity's Cloud Code Assist endpoints.
 *
 * Mirrors the iOS `AntigravityProvider` envelope and response parsing. Only
 * shapes that the iOS implementation already relies on are encoded here.
 * Nothing is guessed: unknown fields are ignored, and unknown endpoints are
 * not invented.
 *
 * This file has no Android dependencies so it can be unit-tested on the JVM.
 */
object AntigravityProtocol {
    const val CLIENT_NAME = "antigravity"
    const val REQUEST_TYPE = "agent"
    const val USER_AGENT = "antigravity/1.107.0 android/aarch64"

    /** Same probe order as the iOS `AntigravityOAuthManager.cloudCodeBaseURLs`. */
    val BASE_URLS: List<String> = listOf(
        "https://daily-cloudcode-pa.sandbox.googleapis.com",
        "https://cloudcode-pa.googleapis.com",
    )

    /** Relative path under the base URL for a generate call. */
    fun methodPath(stream: Boolean): String =
        if (stream) "v1internal:streamGenerateContent?alt=sse" else "v1internal:generateContent"

    /**
     * Wrap an inner Gemini request in the Antigravity envelope
     * (iOS `wrapEnvelope`). The session id is written into the inner request.
     */
    fun wrapEnvelope(
        model: String,
        project: String,
        sessionId: String,
        requestId: String,
        inner: JSONObject,
    ): JSONObject {
        inner.put("sessionId", sessionId)
        return JSONObject()
            .put("model", model)
            .put("userAgent", CLIENT_NAME)
            .put("requestType", REQUEST_TYPE)
            .put("project", project)
            .put("requestId", requestId)
            .put("request", inner)
    }

    /** A function call requested by the model. The args are kept as JSON for the agent loop. */
    data class FunctionCall(
        val name: String,
        val args: JSONObject,
        val thoughtSignature: String?,
    )

    data class Usage(
        val promptTokens: Int,
        val candidateTokens: Int,
        val thoughtTokens: Int,
        val cachedTokens: Int,
    )

    /** One parsed generate response, or one parsed stream event. */
    data class Chunk(
        val text: String,
        val functionCalls: List<FunctionCall>,
        val finishReason: String?,
        val usage: Usage?,
        val modelVersion: String?,
    )

    /** Antigravity wraps the Gemini response as `{"response": {...}}`. */
    private fun unwrap(json: JSONObject): JSONObject = json.optJSONObject("response") ?: json

    /**
     * Parse one response body or one stream event. Parts flagged `thought: true`
     * are skipped so reasoning text never ends up in the visible answer.
     */
    fun parseChunk(json: JSONObject): Chunk {
        val effective = unwrap(json)
        val candidate = effective.optJSONArray("candidates")?.optJSONObject(0)
        val parts = candidate?.optJSONObject("content")?.optJSONArray("parts")

        val text = StringBuilder()
        val calls = mutableListOf<FunctionCall>()
        if (parts != null) {
            for (i in 0 until parts.length()) {
                val part = parts.optJSONObject(i) ?: continue
                if (part.optBoolean("thought", false)) continue
                if (part.has("text")) text.append(part.optString("text"))
                val call = part.optJSONObject("functionCall")
                if (call != null) {
                    calls += FunctionCall(
                        name = call.optString("name"),
                        args = call.optJSONObject("args") ?: JSONObject(),
                        thoughtSignature = part.optString("thoughtSignature").ifEmpty { null },
                    )
                }
            }
        }

        val usageJson = effective.optJSONObject("usageMetadata")
        val usage = usageJson?.let {
            Usage(
                promptTokens = it.optInt("promptTokenCount"),
                candidateTokens = it.optInt("candidatesTokenCount"),
                thoughtTokens = it.optInt("thoughtsTokenCount"),
                cachedTokens = it.optInt("cachedContentTokenCount"),
            )
        }

        return Chunk(
            text = text.toString(),
            functionCalls = calls,
            finishReason = candidate?.optString("finishReason")?.ifEmpty { null },
            usage = usage,
            modelVersion = effective.optString("modelVersion").ifEmpty { null },
        )
    }

    /** Map the Gemini finish reason to the names the OpenMinis agent loop uses. */
    fun mapFinishReason(raw: String?): String? = when {
        raw.isNullOrEmpty() -> null
        raw == "STOP" -> "end_turn"
        raw == "MAX_TOKENS" -> "max_tokens"
        else -> raw.lowercase()
    }

    /**
     * Payload of one server-sent event line, or null for comments, blank
     * lines, `[DONE]`, and malformed JSON. Malformed events are skipped, as
     * on iOS, so one bad event does not end the whole stream.
     */
    fun parseSseLine(line: String): JSONObject? {
        if (!line.startsWith("data:")) return null
        val payload = line.removePrefix("data:").trim()
        if (payload.isEmpty() || payload == "[DONE]") return null
        return try {
            JSONObject(payload)
        } catch (_: JSONException) {
            null
        }
    }

    enum class ErrorKind { AUTH_REJECTED, FORBIDDEN, RATE_LIMITED, SERVER, CLIENT, UNKNOWN }

    /**
     * A classified HTTP failure. [message] is safe to show in the UI: it never
     * contains tokens and never contains the raw response body, only the short
     * `error.message` field when the service provides one.
     */
    data class HttpFailure(val kind: ErrorKind, val status: Int, val message: String)

    fun classifyHttpError(status: Int, body: String): HttpFailure {
        val detail = serviceMessage(body)
        return when (status) {
            401 -> HttpFailure(
                ErrorKind.AUTH_REJECTED, status,
                "Antigravity sign-in has expired or was revoked. Sign in again.",
            )
            403 -> HttpFailure(
                ErrorKind.FORBIDDEN, status,
                listOf("Antigravity access was denied for this account.", detail)
                    .filter { it.isNotEmpty() }.joinToString(" "),
            )
            429 -> HttpFailure(
                ErrorKind.RATE_LIMITED, status,
                "Antigravity rate limit reached. Try again later.",
            )
            in 500..599 -> HttpFailure(
                ErrorKind.SERVER, status,
                "Antigravity is unavailable right now. Try again later.",
            )
            in 400..499 -> HttpFailure(
                ErrorKind.CLIENT, status,
                listOf("Antigravity rejected the request.", detail)
                    .filter { it.isNotEmpty() }.joinToString(" "),
            )
            else -> HttpFailure(
                ErrorKind.UNKNOWN, status,
                "Unexpected response from Antigravity.",
            )
        }
    }

    private fun serviceMessage(body: String): String {
        val message = try {
            JSONObject(body).optJSONObject("error")?.optString("message").orEmpty()
        } catch (_: JSONException) {
            ""
        }
        return message.take(160)
    }
}
