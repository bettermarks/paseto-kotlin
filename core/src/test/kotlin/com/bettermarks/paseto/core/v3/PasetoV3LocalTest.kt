package com.bettermarks.paseto.core.v3

import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.SecretKey
import com.bettermarks.paseto.core.TestVectors
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.Version
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class PasetoV3LocalTest {
  @ParameterizedTest(name = "Encrypt {0}")
  @MethodSource("testVectors")
  fun encrypt(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      secretKey: SecretKey,
      nonce: ByteArray,
      payload: String?,
      footer: String,
      token: String,
      implicitAssertion: String
  ) {
    if (expectFail) {
      assertNotEquals(
          token, PasetoV3Local.encrypt(secretKey, nonce, payload ?: "", footer, implicitAssertion))
    } else {
      assertEquals(
          token, PasetoV3Local.encrypt(secretKey, nonce, payload ?: "", footer, implicitAssertion))
    }
  }

  @ParameterizedTest(name = "Decrypt {0}")
  @MethodSource("testVectors")
  fun decrypt(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      secretKey: SecretKey,
      @Suppress("UNUSED_PARAMETER") nonce: ByteArray,
      payload: String?,
      footer: String,
      token: String,
      implicitAssertion: String
  ) {
    val parsedToken = Token.parse(token)
    if (expectFail) {
      try {
        val (message, _) = PasetoV3Local.decrypt(secretKey, parsedToken, implicitAssertion)
        assertNotEquals(payload, message)
      } catch (_: PasetoException) {}
    } else {
      val (actualMessage, actualFooter) =
          PasetoV3Local.decrypt(secretKey, parsedToken, implicitAssertion)
      assertEquals(payload ?: "", actualMessage)
      assertEquals(footer, actualFooter)
    }
  }

  companion object {
    @JvmStatic
    fun testVectors(): List<Arguments> =
        TestVectors.read(Version.V3, Purpose.Local).map { vector ->
          Arguments.of(
              vector.name,
              vector.expectFail,
              vector.key(Version.V3),
              vector.nonce,
              vector.payload,
              vector.footer,
              vector.token,
              vector.implicitAssertion)
        }
  }
}
