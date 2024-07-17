package com.bettermarks.paseto

import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.PrivateKey
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.SecretKey
import com.bettermarks.paseto.core.SigningKey
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.VerificationKey
import com.bettermarks.paseto.core.Version
import com.bettermarks.paseto.core.v1.PasetoV1Local
import com.bettermarks.paseto.core.v1.PasetoV1Public
import com.bettermarks.paseto.core.v2.PasetoV2Local
import com.bettermarks.paseto.core.v2.PasetoV2Public
import com.bettermarks.paseto.core.v3.PasetoV3Local
import com.bettermarks.paseto.core.v3.PasetoV3Public
import com.bettermarks.paseto.core.v4.PasetoV4Local
import com.bettermarks.paseto.core.v4.PasetoV4Public
import java.time.Duration
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class Paseto(
    val signingKey: SigningKey? = null,
    val verificationKeyLookup: ((kid: String?) -> VerificationKey?)? = null,
    val tokenTtl: Duration? = null,
    val leeway: Duration? = null,
    val requiresExpiresAt: Boolean = false,
    val requiresIssuedAt: Boolean = false,
    val subject: String? = null,
    val issuer: String? = null,
    val audience: String? = null,
    val implicitAssertion: String? = null,
) {
  fun createToken(): String {
    if (signingKey == null) throw PasetoException("No signing key configured")

    val tokenContent = createTokenContent()

    return when (signingKey.version to signingKey.purpose) {
      Version.V1 to Purpose.Local -> PasetoV1Local.encrypt(signingKey as SecretKey, tokenContent)
      Version.V1 to Purpose.Public -> PasetoV1Public.sign(signingKey as PrivateKey, tokenContent)
      Version.V2 to Purpose.Local -> PasetoV2Local.encrypt(signingKey as SecretKey, tokenContent)
      Version.V2 to Purpose.Public -> PasetoV2Public.sign(signingKey as PrivateKey, tokenContent)
      Version.V3 to Purpose.Local ->
          PasetoV3Local.encrypt(signingKey as SecretKey, tokenContent, implicitAssertion ?: "")
      Version.V3 to Purpose.Public ->
          PasetoV3Public.sign(signingKey as PrivateKey, tokenContent, implicitAssertion ?: "")
      Version.V4 to Purpose.Local ->
          PasetoV4Local.encrypt(signingKey as SecretKey, tokenContent, implicitAssertion ?: "")
      Version.V4 to Purpose.Public ->
          PasetoV4Public.sign(signingKey as PrivateKey, tokenContent, implicitAssertion ?: "")
      else ->
          throw PasetoException("Invalid signing key ${signingKey.version} ${signingKey.purpose}")
    }
  }

  private fun createTokenContent(): TokenContent {
    val now = Instant.now()
    val message =
        json.encodeToString(
            StandardClaims(
                issuedAt = now,
                expiration = tokenTtl?.let { now + it },
                subject = subject,
                issuer = issuer,
                audience = audience,
            ))
    val footer = signingKey?.id?.let { json.encodeToString(StandardFooter(keyId = it)) }

    return TokenContent(message, footer ?: "")
  }

  companion object {
    val json = Json {
      ignoreUnknownKeys = true
      prettyPrint = false
    }
  }
}
