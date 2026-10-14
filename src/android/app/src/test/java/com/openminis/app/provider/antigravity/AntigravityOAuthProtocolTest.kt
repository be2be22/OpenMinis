package com.openminis.app.provider.antigravity

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AntigravityOAuthProtocolTest {

    @Test
    fun `pkce challenge matches the RFC 7636 example`() {
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            AntigravityOAuthProtocol.codeChallenge(verifier),
        )
    }

    @Test
    fun `generated verifier and state are url safe and not reused`() {
        val verifier = AntigravityOAuthProtocol.newVerifier()
        val state = AntigravityOAuthProtocol.newState()

        assertTrue(verifier.length >= 43)
        assertTrue(verifier.matches(Regex("[A-Za-z0-9_-]+")))
        assertTrue(state.matches(Regex("[A-Za-z0-9_-]+")))
        assertFalse(verifier == AntigravityOAuthProtocol.newVerifier())
        assertFalse(state == AntigravityOAuthProtocol.newState())
    }

    @Test
    fun `authorization url uses pkce s256 state and no client secret`() {
        val url = AntigravityOAuthProtocol.buildAuthorizationUrl(
            clientId = "my-android-client.apps.googleusercontent.com",
            redirectUri = "com.googleusercontent.apps.my-android-client:/oauth2redirect",
            state = "state-123",
            codeChallenge = "challenge-abc",
        )

        assertTrue(url.startsWith(AntigravityOAuthProtocol.AUTH_ENDPOINT + "?"))
        assertTrue(url.contains("client_id=my-android-client.apps.googleusercontent.com"))
        assertTrue(url.contains("response_type=code"))
        assertTrue(url.contains("code_challenge=challenge-abc"))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("state=state-123"))
        assertTrue(url.contains("access_type=offline"))
        assertTrue(url.contains("prompt=consent"))
        assertTrue(url.contains("redirect_uri=com.googleusercontent.apps.my-android-client%3A%2Foauth2redirect"))
        assertTrue(url.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform"))
        assertFalse(url.contains("client_secret"))
    }

    @Test
    fun `authorization url refuses a blank client id`() {
        try {
            AntigravityOAuthProtocol.buildAuthorizationUrl("", "r", "s", "c")
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `state validation accepts only the exact value`() {
        assertTrue(AntigravityOAuthProtocol.isStateValid("abc", "abc"))
        assertFalse(AntigravityOAuthProtocol.isStateValid("abc", "abd"))
        assertFalse(AntigravityOAuthProtocol.isStateValid("abc", null))
        assertFalse(AntigravityOAuthProtocol.isStateValid(null, "abc"))
        assertFalse(AntigravityOAuthProtocol.isStateValid("", ""))
    }

    @Test
    fun `code exchange and refresh forms carry no client secret`() {
        val code = AntigravityOAuthProtocol.authorizationCodeForm("cid", "code-1", "redir", "verifier-1")
        val refresh = AntigravityOAuthProtocol.refreshForm("cid", "refresh-1")

        assertEquals("authorization_code", code["grant_type"])
        assertEquals("verifier-1", code["code_verifier"])
        assertEquals("refresh_token", refresh["grant_type"])
        assertEquals("refresh-1", refresh["refresh_token"])
        assertFalse(code.containsKey("client_secret"))
        assertFalse(refresh.containsKey("client_secret"))
    }

    @Test
    fun `token response sets expiry from expires_in`() {
        val json = JSONObject("""{"access_token":"a1","refresh_token":"r1","expires_in":3600}""")
        val tokens = AntigravityOAuthProtocol.parseTokenResponse(json, nowMillis = 1_000_000L)

        assertEquals("a1", tokens.accessToken)
        assertEquals("r1", tokens.refreshToken)
        assertEquals(1_000_000L + 3_600_000L, tokens.expiresAtMillis)
    }

    @Test
    fun `refresh response keeps the previous refresh token when none is returned`() {
        val json = JSONObject("""{"access_token":"a2","expires_in":3600}""")
        val tokens = AntigravityOAuthProtocol.parseTokenResponse(
            json, nowMillis = 0L, previousRefreshToken = "r1",
        )

        assertEquals("a2", tokens.accessToken)
        assertEquals("r1", tokens.refreshToken)
    }

    @Test
    fun `token response without an access token is rejected`() {
        try {
            AntigravityOAuthProtocol.parseTokenResponse(JSONObject("{}"), nowMillis = 0L)
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `token counts as expired inside the skew window before real expiry`() {
        val tokens = AntigravityOAuthProtocol.Tokens("a", "r", expiresAtMillis = 1_000_000L)

        assertFalse(AntigravityOAuthProtocol.isExpired(tokens, nowMillis = 0L))
        assertTrue(AntigravityOAuthProtocol.isExpired(tokens, nowMillis = 1_000_000L - 30_000L))
        assertTrue(AntigravityOAuthProtocol.isExpired(tokens, nowMillis = 2_000_000L))
    }

    @Test
    fun `invalid_grant ends the session but a server error stays transient`() {
        assertEquals(
            AntigravityOAuthProtocol.TokenError.ReauthRequired,
            AntigravityOAuthProtocol.classifyTokenError(400, """{"error":"invalid_grant"}"""),
        )
        assertEquals(
            AntigravityOAuthProtocol.TokenError.ReauthRequired,
            AntigravityOAuthProtocol.classifyTokenError(401, "{}"),
        )
        assertEquals(
            AntigravityOAuthProtocol.TokenError.Transient(500),
            AntigravityOAuthProtocol.classifyTokenError(500, "not json"),
        )
    }

    @Test
    fun `scopes include cloud access and identity only`() {
        assertEquals(3, AntigravityOAuthProtocol.SCOPES.size)
        assertNull(AntigravityOAuthProtocol.SCOPES.find { it.contains("cclog") })
    }
}
