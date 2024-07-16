package com.bettermarks.paseto.core.v4

import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.PrivateKey
import com.bettermarks.paseto.core.PublicKey
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.TestVectors
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.Version
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class PasetoV4PublicTest {
  @ParameterizedTest(name = "Sign {0}")
  @MethodSource("testVectors")
  fun sign(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      @Suppress("UNUSED_PARAMETER") publicKey: PublicKey,
      privateKey: PrivateKey,
      payload: String?,
      footer: String,
      token: String,
      implicitAssertion: String
  ) {
    val actualToken =
        PasetoV4Public.sign(privateKey, TokenContent(payload ?: "", footer), implicitAssertion)

    if (expectFail) assertNotEquals(token, actualToken) else assertEquals(token, actualToken)
  }

  @ParameterizedTest(name = "Verify {0}")
  @MethodSource("testVectors")
  fun verify(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      publicKey: PublicKey,
      @Suppress("UNUSED_PARAMETER") privateKey: PrivateKey,
      payload: String?,
      footer: String,
      token: String,
      implicitAssertion: String
  ) {
    val parsedToken = Token.parse(token)

    if (expectFail) {
      assertThrows<PasetoException> {
        PasetoV4Public.verify(publicKey, parsedToken, implicitAssertion)
      }
    } else {
      val (actualMessage, actualFooter) =
          PasetoV4Public.verify(publicKey, parsedToken, implicitAssertion)

      assertEquals(payload, actualMessage)
      assertEquals(footer, actualFooter)
    }
  }

  companion object {
    @JvmStatic
    fun testVectors(): List<Arguments> =
        TestVectors.read(Version.V4, Purpose.Public).map { vector ->
          Arguments.of(
              vector.name,
              vector.expectFail,
              vector.publicKey(Version.V4),
              vector.privateKey(Version.V4),
              vector.payload,
              vector.footer,
              vector.token,
              vector.implicitAssertion)
        }
  }
}
