package com.openminis.app.auth

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * Receives the Google redirect for the Antigravity Android OAuth client.
 *
 * The URI has the form `com.googleusercontent.apps.<client-id>:/oauth2redirect?code=...&state=...`.
 * The intent filter is built from the configured client id via a manifest placeholder,
 * so only the registered scheme reaches this activity. The activity finishes at once,
 * and the waiting [AntigravityOAuthManager.login] call completes the exchange.
 */
class AntigravityRedirectActivity : Activity() {

    companion object {
        private const val TAG = "AntigravityRedirect"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent?.data
        // The query carries the code and state. Only log the scheme and path.
        Log.i(TAG, "Antigravity redirect received (${uri?.scheme}:${uri?.path})")
        val delivered = uri != null && AntigravityOAuthManager.deliverRedirect(uri)
        if (!delivered) {
            Log.w(TAG, "No sign-in was waiting for this redirect")
        }
        finish()
    }
}
