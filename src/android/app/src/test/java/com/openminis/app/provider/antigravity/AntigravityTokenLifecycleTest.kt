package com.openminis.app.provider.antigravity

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mocked-only checks for the Antigravity token lifecycle and the tool-call
 * continuation shape. They use no Android context and no network, so they run
 * in the JVM unit-test task. They do not prove that Google accepts the flow
 * or that a real Antigravity account can call the service.
 */
class AntigravityTokenLifecycleTest {

    @Test
    fun refreshKeepsTheStoredRefreshTokenWhenGoogleOmitsIt() {
        // Google omits refresh_token on a refresh response. The previous one must survive.
        val refreshed = AntigravityOAuthProtocol.parseTokenResponse(
            JSONObject("""{"access_token":"new-access","expires_in":3600}"""),
            nowMillis = 1_000L,
            previousRefreshToken = "old-refresh",
        )

        assertEquals("new-access", refreshed.accessToken)
        assertEquals("old-refresh", refreshed.refreshToken)
        assertEquals(1_000L + 3_600_000L, refreshed.expiresAtMillis)
    }

    @Test
    fun refreshReplacesTheRefreshTokenWhenGoogleRotatesIt() {
        val rotated = AntigravityOAuthProtocol.parseTokenResponse(
            JSONObject("""{"access_token":"a","refresh_token":"rotated","expires_in":60}"""),
            nowMillis = 0L,
            previousRefreshToken = "old",
        )

        assertEquals("rotated", rotated.refreshToken)
    }

    @Test
    fun refreshRequestCarriesNoClientSecretAndUsesRefreshGrant() {
        val form = AntigravityOAuthProtocol.refreshForm(clientId = "cid", refreshToken = "rt")

        assertEquals("refresh_token", form["grant_type"])
        assertEquals("rt", form["refresh_token"])
        assertEquals("cid", form["client_id"])
        assertFalse(form.containsKey("client_secret"))
    }

    @Test
    fun rejectedGrantsEndTheSessionButServerErrorsDoNot() {
        // Only the grant-level rejections require a fresh sign-in.
        for (code in listOf("invalid_grant", "invalid_client", "unauthorized_client", "access_denied")) {
            assertTrue(
                "expected $code to require sign-in",
                AntigravityOAuthProtocol.classifyTokenError(400, """{"error":"$code"}""") ==
                    AntigravityOAuthProtocol.TokenError.ReauthRequired,
            )
        }
        assertTrue(
            AntigravityOAuthProtocol.classifyTokenError(503, "") is AntigravityOAuthProtocol.TokenError.Transient,
        )
        assertTrue(
            AntigravityOAuthProtocol.classifyTokenError(429, "") is AntigravityOAuthProtocol.TokenError.Transient,
        )
    }

    @Test
    fun expiredAccessTokenIsDetectedInsideTheSkewWindow() {
        val tokens = AntigravityOAuthProtocol.Tokens("a", "r", expiresAtMillis = 10_000_000L)

        assertFalse(AntigravityOAuthProtocol.isExpired(tokens, nowMillis = 1_000_000L))
        assertTrue(AntigravityOAuthProtocol.isExpired(tokens, nowMillis = 10_000_000L - 1L))
    }

    @Test
    fun rejectedCredentialsHaveAClearUserMessageWithoutRawBody() {
        val failure = AntigravityProtocol.classifyHttpError(
            401,
            """{"error":{"message":"Request had invalid authentication credentials","status":"UNAUTHENTICATED"}}""",
        )

        assertEquals(AntigravityProtocol.ErrorKind.AUTH_REJECTED, failure.kind)
        assertTrue(failure.message.contains("Sign in again"))
    }

    @Test
    fun toolCallContinuationKeepsTheToolNameAndArgsForTheResultTurn() {
        // The agent loop replays the functionCall it received, then appends a
        // functionResponse with the same name. The protocol parser must keep the name
        // and args exactly so that replay matches.
        val json = JSONObject(
            """
            {"response":{"candidates":[{"content":{"parts":[
              {"functionCall":{"name":"read_file","args":{"path":"notes.md"}},"thoughtSignature":"sig-7"}
            ]},"finishReason":"STOP"}]}}
            """.trimIndent(),
        )

        val chunk = AntigravityProtocol.parseChunk(json)

        assertEquals(1, chunk.functionCalls.size)
        val call = chunk.functionCalls[0]
        assertEquals("read_file", call.name)
        assertEquals("notes.md", call.args.getString("path"))
        assertEquals("sig-7", call.thoughtSignature)
    }

    @Test
    fun toolCallWithoutSignatureStillParsesWithNullSignature() {
        val json = JSONObject(
            """{"candidates":[{"content":{"parts":[{"functionCall":{"name":"list_dir","args":{}}}]}}]}""",
        )

        val call = AntigravityProtocol.parseChunk(json).functionCalls.single()

        assertEquals("list_dir", call.name)
        assertEquals(null, call.thoughtSignature)
    }
}
