package com.openminis.app.auth

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import com.openminis.app.BuildConfig
import com.openminis.app.provider.antigravity.AntigravityOAuthProtocol
import kotlinx.coroutines.CompletableDeferred
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
 * Antigravity sign-in manager for Android.
 *
 * Flow: Google OAuth authorization code with PKCE and a `state` check, for an
 * Android OAuth client. Google's Android client type has no client secret and
 * uses a redirect of the form `com.googleusercontent.apps.<client-id>:/oauth2redirect`.
 * The system browser sends the user back to the app, and [AntigravityRedirectActivity]
 * hands the URI to [complete]. No localhost listener is used, since a phone cannot
 * receive a localhost callback from the browser.
 *
 * The client id comes from the build-time setting ANTIGRAVITY_OAUTH_CLIENT_ID in
 * provider-customization.properties. It is empty in the public mirror. In that case
 * [isConfigured] is false and [login] fails with a setup message before any browser
 * opens. No secret and no other product's client id is used.
 */
class AntigravityOAuthManager(
    context: Context,
    instanceId: String,
    private val configuredClientId: String = BuildConfig.ANTIGRAVITY_OAUTH_CLIENT_ID,
    private val tokenEndpoint: String = AntigravityOAuthProtocol.TOKEN_ENDPOINT,
    private val httpCall: (Request) -> Pair<Int, String> = { request -> defaultHttp(request) },
    private val clock: () -> Long = System::currentTimeMillis,
) : OAuthManager(context, instanceId) {

    companion object {
        private const val TAG = "AntigravityOAuth"
        private const val KEY_EMAIL = "email"
        private const val KEY_PROJECT = "gcp_project"
        private const val KEY_BASE_URL = "base_url"
        private const val KEY_PENDING_STATE = "pending_state"
        private const val KEY_PENDING_VERIFIER = "pending_verifier"

        private val refreshLock = Mutex()

        /** Set by [AntigravityRedirectActivity] when the browser returns. */
        @Volatile
        private var pendingCallback: CompletableDeferred<Uri>? = null

        /** Delivers the redirect URI to the waiting [login] call. Returns false if nothing waits. */
        fun deliverRedirect(uri: Uri): Boolean {
            val waiter = pendingCallback ?: return false
            return waiter.complete(uri)
        }

        /** Android redirect scheme for a client id: the reversed-looking Google form. */
        fun redirectScheme(clientId: String): String = "com.googleusercontent.apps." + clientId.removeSuffix(".apps.googleusercontent.com")

        /** The redirect URI registered for the Android client. */
        fun androidRedirectUri(clientId: String): String = redirectScheme(clientId) + ":/oauth2redirect"

        private fun defaultHttp(request: Request): Pair<Int, String> =
            OAuthManager.httpClient.newCall(request).execute().use { res ->
                res.code to res.body?.string().orEmpty()
            }

        /**
         * Start sign-in for [instanceId]: opens the browser, waits for the redirect,
         * exchanges the code, and stores the tokens. Returns a masked-safe status string.
         */
        suspend fun login(
            context: Context,
            instanceId: String,
            providerRepository: com.openminis.app.data.repository.ProviderRepository,
        ): String {
            val manager = AntigravityOAuthManager(context, instanceId)
            manager.requireConfigured()
            return manager.performLogin(context)
        }
    }

    /** True when a client id is configured for this build. */
    val isConfigured: Boolean get() = configuredClientId.isNotBlank()

    override val authURL: String = AntigravityOAuthProtocol.AUTH_ENDPOINT
    override val tokenURL: String = tokenEndpoint
    override val clientId: String get() = configuredClientId

    /** Android public client: there is no secret. */
    override val clientSecret: String? = null
    override val callbackPort: Int = 0
    override val redirectPath: String = "/oauth2redirect"
    override val scopes: String = AntigravityOAuthProtocol.SCOPES.joinToString(" ")

    /** The Android redirect URI, built from the client id. Not a localhost URL. */
    override val redirectUri: String get() = androidRedirectUri(configuredClientId)

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

    /** Throws with a user-facing setup message when no client id is configured. */
    fun requireConfigured() {
        check(isConfigured) {
            "Antigravity sign-in needs a Google OAuth client for this build. " +
                "Set ANTIGRAVITY_OAUTH_CLIENT_ID in app/provider-customization.properties " +
                "to an Android client for com.openminis.app, then rebuild."
        }
    }

    /**
     * Opens the browser with the authorization URL and waits for the redirect.
     * A 5-minute timeout keeps the sign-in screen from waiting forever.
     */
    suspend fun performLogin(context: Context): String {
        val verifier = generateAndSavePKCE().first
        val state = generateAndSaveState()
        saveOAuthString(KEY_PENDING_STATE, state)
        saveOAuthString(KEY_PENDING_VERIFIER, verifier)

        val url = AntigravityOAuthProtocol.buildAuthorizationUrl(
            clientId = clientId,
            redirectUri = redirectUri,
            state = state,
            codeChallenge = AntigravityOAuthProtocol.codeChallenge(verifier),
        )
        val waiter = CompletableDeferred<Uri>()
        pendingCallback = waiter
        try {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            val uri = kotlinx.coroutines.withTimeout(5 * 60 * 1000L) { waiter.await() }
            complete(uri)
            return "signed-in"
        } finally {
            if (pendingCallback === waiter) pendingCallback = null
        }
    }

    /**
     * Handles the redirect URI: checks the error and state, exchanges the code with
     * the stored PKCE verifier, and stores the tokens.
     */
    suspend fun complete(uri: Uri) {
        val error = uri.getQueryParameter("error")
        if (error != null) {
            throw IllegalStateException("Google sign-in was not completed (${error.take(60)}).")
        }
        val expectedState = loadOAuthString(KEY_PENDING_STATE)
        val receivedState = uri.getQueryParameter("state")
        if (!AntigravityOAuthProtocol.isStateValid(expectedState, receivedState)) {
            throw IllegalStateException("Google sign-in response did not match this request. Try again.")
        }
        val code = uri.getQueryParameter("code")
            ?: throw IllegalStateException("Google sign-in returned no authorization code.")
        val verifier = loadOAuthString(KEY_PENDING_VERIFIER)
            ?: throw IllegalStateException("Sign-in session expired. Try again.")
        exchangeCode(code, verifier)
        saveOAuthString(KEY_PENDING_STATE, "")
        saveOAuthString(KEY_PENDING_VERIFIER, "")
    }

    private suspend fun exchangeCode(code: String, verifier: String) {
        val form = AntigravityOAuthProtocol.authorizationCodeForm(clientId, code, redirectUri, verifier)
        val (status, body) = withContext(Dispatchers.IO) {
            httpCall(formRequest(tokenEndpoint, form))
        }
        if (status !in 200..299) {
            // Never log the body: it can echo request material.
            Log.w(TAG, "Antigravity token exchange failed (status $status)")
            throw IllegalStateException("Google did not accept the sign-in (status $status). Try again.")
        }
        val json = try {
            JSONObject(body)
        } catch (_: Exception) {
            throw IllegalStateException("Google returned an unreadable sign-in response.")
        }
        storeTokenResponse(json)
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
        for (key in listOf(KEY_EMAIL, KEY_PROJECT, KEY_BASE_URL, KEY_PENDING_STATE, KEY_PENDING_VERIFIER)) {
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
        val state = generateAndSaveState()
        saveOAuthString(KEY_PENDING_STATE, state)
        saveOAuthString(KEY_PENDING_VERIFIER, verifier)
        return AntigravityOAuthProtocol.buildAuthorizationUrl(
            clientId = clientId,
            redirectUri = redirectUri,
            state = state,
            codeChallenge = AntigravityOAuthProtocol.codeChallenge(verifier),
        )
    }
}
