package com.openminis.app.auth

import android.content.Context
import android.util.Log
import com.openminis.app.provider.antigravity.AntigravityOAuthProtocol
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.URLEncoder

/**
 * Antigravity sign-in manager.
 *
 * Google OAuth authorization code flow with PKCE for a public client. No client
 * secret is stored or sent. [clientId] is empty until a Google OAuth client is
 * registered for the OpenMinis Android package. Until then [isConfigured] is
 * false and sign-in refuses to start with a clear message.
 *
 * Tokens live in the same encrypted store as the other OAuth managers. Concurrent
 * callers share one refresh through [refreshLock], so a refresh token is never
 * spent twice.
 *
 * The iOS manager and the earlier scaffold used a placeholder secret and a
 * client id that belongs to another product. Both are removed here.
 */
class AntigravityOAuthManager(
    context: Context,
    instanceId: String,
    private val clientId: String = CLIENT_ID,
    private val tokenEndpoint: String = AntigravityOAuthProtocol.TOKEN_ENDPOINT,
    private val httpCall: (Request) -> Pair<Int, String> = { request -> defaultHttp(request) },
    private val clock: () -> Long = System::currentTimeMillis,
) : OAuthManager(context, instanceId) {

    companion object {
        private const val TAG = "AntigravityOAuth"
        private const val KEY_EMAIL = "email"
        private const val KEY_PROJECT = "gcp_project"
        private const val KEY_BASE_URL = "base_url"

        /**
         * Google OAuth client id registered for OpenMinis on Android. Empty until
         * such a client exists. Do not paste an id from another product here.
         */
        const val CLIENT_ID: String = ""

        private val refreshLock = Mutex()

        private fun defaultHttp(request: Request): Pair<Int, String> =
            httpClient.newCall(request).execute().use { res ->
                res.code to res.body?.string().orEmpty()
            }
    }

    /** True when a client id is configured for this build. */
    val isConfigured: Boolean get() = clientId.isNotBlank()

    override val authURL: String = AntigravityOAuthProtocol.AUTH_ENDPOINT
    override val tokenURL: String = tokenEndpoint
    override val clientId: String get() = this@AntigravityOAuthManager.clientId

    /** Public client: there is no secret. */
    override val clientSecret: String? = null
    override val callbackPort: Int = 8086
    override val redirectPath: String = "/oauth2callback"
    override val scopes: String = AntigravityOAuthProtocol.SCOPES.joinToString(" ")

    /** Google account email, cached for display. */
    var email: String?
        get() = loadOAuthString(KEY_EMAIL)
        private set(value) { value?.let { saveOAuthString(KEY_EMAIL, it) } }

    /** Cloud project id discovered at sign-in. */
    var gcpProjectId: String?
        get() = loadOAuthString(KEY_PROJECT)
        set(value) { value?.let { saveOAuthString(KEY_PROJECT, it) } }

    /** Base URL that answered the project discovery. */
    var activeBaseURL: String?
        get() = loadOAuthString(KEY_BASE_URL)
        set(value) { value?.let { saveOAuthString(KEY_BASE_URL, it) } }

    /** Throws when sign-in cannot start because no client id is configured. */
    fun requireConfigured() {
        check(isConfigured) {
            "Antigravity sign-in is not configured for this build. " +
                "A Google OAuth client for OpenMinis is required."
        }
    }

    /**
     * Store a token response. Google omits the refresh token on a refresh, so the
     * previous one is kept.
     */
    fun storeTokenResponse(json: JSONObject) {
        val previous = loadStoredTokens()?.optString("refresh_token")?.ifEmpty { null }
        val tokens = AntigravityOAuthProtocol.parseTokenResponse(json, clock(), previous)
        val blob = JSONObject()
            .put("access_token", tokens.accessToken)
            .put("expire_at", tokens.expiresAtMillis)
        tokens.refreshToken?.let { blob.put("refresh_token", it) }
        saveOAuthString("tokens", blob.toString())
    }

    /**
     * A usable access token, refreshed when close to expiry. Returns null when the
     * user must sign in again. A transient failure returns null but keeps the
     * stored tokens, so the next call can try again.
     */
    override suspend fun validAccessToken(): String? {
        loadManualBearerToken()?.takeIf { it.isNotEmpty() }?.let { return it }
        val stored = loadStoredTokens() ?: return null
        val accessToken = stored.optString("access_token").ifEmpty { return null }
        val tokens = AntigravityOAuthProtocol.Tokens(
            accessToken = accessToken,
            refreshToken = stored.optString("refresh_token").ifEmpty { null },
            expiresAtMillis = stored.optLong("expire_at", 0L),
        )
        if (!AntigravityOAuthProtocol.isExpired(tokens, clock())) return accessToken
        return refreshLocked(tokens.refreshToken)
    }

    /** Refreshes the access token. Concurrent callers share one refresh. */
    override suspend fun refreshToken(): Boolean {
        val refresh = loadStoredTokens()?.optString("refresh_token")?.ifEmpty { null }
        return refreshLocked(refresh) != null
    }

    private suspend fun refreshLocked(refreshToken: String?): String? = refreshLock.withLock {
        // Another caller may have refreshed while this one waited for the lock.
        val current = loadStoredTokens()
        val currentToken = current?.optString("access_token").orEmpty()
        val currentExpiry = current?.optLong("expire_at", 0L) ?: 0L
        if (currentToken.isNotEmpty() && !AntigravityOAuthProtocol.isExpired(
                AntigravityOAuthProtocol.Tokens(currentToken, null, currentExpiry), clock(),
            )
        ) {
            return@withLock currentToken
        }
        if (refreshToken.isNullOrEmpty()) return@withLock null

        val (status, body) = withContext(Dispatchers.IO) {
            httpCall(formRequest(tokenEndpoint, AntigravityOAuthProtocol.refreshForm(clientId, refreshToken)))
        }
        if (status !in 200..299) {
            when (val error = AntigravityOAuthProtocol.classifyTokenError(status, body)) {
                is AntigravityOAuthProtocol.TokenError.ReauthRequired -> {
                    markNeedsReauth(refreshToken)
                    Log.w(TAG, "Antigravity refresh rejected; sign-in required")
                }
                is AntigravityOAuthProtocol.TokenError.Transient ->
                    Log.w(TAG, "Antigravity refresh failed temporarily (status ${error.status})")
            }
            return@withLock null
        }
        val json = try {
            JSONObject(body)
        } catch (_: Exception) {
            return@withLock null
        }
        storeTokenResponse(json)
        loadStoredTokens()?.optString("access_token")?.ifEmpty { null }
    }

    /**
     * Signs out: removes the tokens (via the base [logout]) and also clears the
     * cached account, project and base URL, so no account state survives.
     */
    fun signOut() {
        logout()
        clearAccountState()
    }

    private fun clearAccountState() {
        for (key in listOf(KEY_EMAIL, KEY_PROJECT, KEY_BASE_URL)) {
            com.openminis.app.util.EncryptedPrefsFactory.safeCreate(context, "oauth_prefs")
                .edit()
                .remove("oauth_${key}_$instanceId")
                .apply()
        }
    }

    private fun formRequest(url: String, form: Map<String, String>): Request {
        val body = form.entries.joinToString("&") { (k, v) ->
            URLEncoder.encode(k, "UTF-8") + "=" + URLEncoder.encode(v, "UTF-8")
        }
        return Request.Builder()
            .url(url)
            .post(body.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
            .build()
    }

    /** Authorization URL for the sign-in screen. Requires [isConfigured]. */
    override fun buildAuthorizationUrl(): String {
        requireConfigured()
        val verifier = generateAndSavePKCE().first
        return AntigravityOAuthProtocol.buildAuthorizationUrl(
            clientId = clientId,
            redirectUri = redirectUri,
            state = generateAndSaveState(),
            codeChallenge = AntigravityOAuthProtocol.codeChallenge(verifier),
        )
    }
}
