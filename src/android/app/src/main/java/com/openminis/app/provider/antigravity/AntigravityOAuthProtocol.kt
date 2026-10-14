package com.openminis.app.provider.antigravity

import org.json.JSONException
import org.json.JSONObject
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Pure OAuth 2.0 helpers for Antigravity sign-in: authorization code flow with
 * PKCE (S256) and a validated `state` parameter.
 *
 * No client secret is used anywhere. An Android OAuth client is a public
 * client: the token exchange relies on PKCE, not on a secret embedded in the
 * app. This file has no Android dependencies.
 */
object AntigravityOAuthProtocol {
    const val AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    const val TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

    /** Scopes that Google's own sign-in needs for Cloud Code access and identity. */
    val SCOPES: List<String> = listOf(
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    )

    /** Refresh this long before the stated expiry to absorb clock skew. */
    const val EXPIRY_SKEW_MS = 60_000L

    /** Default lifetime when the token response omits `expires_in`. */
    private const val DEFAULT_EXPIRES_IN_SECONDS = 3600L

    /** OAuth error codes that mean the stored grant is dead and the user must sign in again. */
    private val FATAL_ERROR_CODES = setOf(
        "invalid_grant",
        "invalid_token",
        "unauthorized_client",
        "invalid_client",
        "access_denied",
    )

    data class Tokens(
        val accessToken: String,
        val refreshToken: String?,
        val expiresAtMillis: Long,
    )

    sealed class TokenError {
        /** The grant itself is dead. The user must sign in again. */
        object ReauthRequired : TokenError()

        /** Transient failure. Keep the stored tokens and retry later. */
        data class Transient(val status: Int) : TokenError()
    }

    /** PKCE verifier: 64 random bytes, base64url without padding (RFC 7636 length range). */
    fun newVerifier(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(64)
        random.nextBytes(bytes)
        return base64Url(bytes)
    }

    /** PKCE S256 challenge for [verifier]. */
    fun codeChallenge(verifier: String): String =
        base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))

    /** Anti-CSRF `state`: 32 random bytes, base64url without padding. */
    fun newState(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return base64Url(bytes)
    }

    fun buildAuthorizationUrl(
        clientId: String,
        redirectUri: String,
        state: String,
        codeChallenge: String,
    ): String {
        require(clientId.isNotBlank()) { "OAuth client id is not configured" }
        val params = linkedMapOf(
            "client_id" to clientId,
            "redirect_uri" to redirectUri,
            "response_type" to "code",
            "scope" to SCOPES.joinToString(" "),
            "state" to state,
            "code_challenge" to codeChallenge,
            "code_challenge_method" to "S256",
            "access_type" to "offline",
            "prompt" to "consent",
        )
        return AUTH_ENDPOINT + "?" + params.entries.joinToString("&") { (key, value) ->
            encode(key) + "=" + encode(value)
        }
    }

    /**
     * Constant-time comparison of the returned `state` with the one we sent.
     * A missing value on either side never matches.
     */
    fun isStateValid(expected: String?, received: String?): Boolean {
        if (expected.isNullOrEmpty() || received.isNullOrEmpty()) return false
        return MessageDigest.isEqual(
            expected.toByteArray(Charsets.UTF_8),
            received.toByteArray(Charsets.UTF_8),
        )
    }

    /** Form body for the authorization-code exchange. Contains no client secret. */
    fun authorizationCodeForm(
        clientId: String,
        code: String,
        redirectUri: String,
        codeVerifier: String,
    ): Map<String, String> = linkedMapOf(
        "grant_type" to "authorization_code",
        "code" to code,
        "redirect_uri" to redirectUri,
        "client_id" to clientId,
        "code_verifier" to codeVerifier,
    )

    /** Form body for a refresh. Contains no client secret. */
    fun refreshForm(clientId: String, refreshToken: String): Map<String, String> = linkedMapOf(
        "grant_type" to "refresh_token",
        "refresh_token" to refreshToken,
        "client_id" to clientId,
    )

    /**
     * Parse a token response. Google omits `refresh_token` on a refresh, so the
     * previous refresh token is kept in that case.
     */
    fun parseTokenResponse(
        json: JSONObject,
        nowMillis: Long,
        previousRefreshToken: String? = null,
    ): Tokens {
        val access = json.optString("access_token")
        require(access.isNotEmpty()) { "token response has no access token" }
        val expiresIn = json.optLong("expires_in", DEFAULT_EXPIRES_IN_SECONDS)
        val refresh = json.optString("refresh_token").ifEmpty { previousRefreshToken }
        return Tokens(
            accessToken = access,
            refreshToken = refresh,
            expiresAtMillis = nowMillis + expiresIn * 1000L,
        )
    }

    /** True when the access token should be refreshed before use. */
    fun isExpired(tokens: Tokens, nowMillis: Long): Boolean =
        nowMillis + EXPIRY_SKEW_MS >= tokens.expiresAtMillis

    /**
     * Decide what a failed token-endpoint call means. Only a fatal OAuth error
     * or an auth-rejection status ends the grant. Everything else is treated as
     * transient so a network blip never logs the user out.
     */
    fun classifyTokenError(status: Int, body: String): TokenError {
        val code = try {
            JSONObject(body).optString("error").lowercase()
        } catch (_: JSONException) {
            ""
        }
        val fatal = code in FATAL_ERROR_CODES || status == 401 || status == 403
        return if (fatal) TokenError.ReauthRequired else TokenError.Transient(status)
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
