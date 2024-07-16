package com.bettermarks.paseto.core.v2

import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.SecretKey
import com.bettermarks.paseto.core.TestVectors
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.Version
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class PasetoV2LocalTest {
  @ParameterizedTest(name = "Encrypt {0}")
  @MethodSource("testVectors")
  fun encrypt(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      secretKey: SecretKey,
      nonce: ByteArray,
      payload: String?,
      footer: String,
      token: String
  ) {
    if (expectFail) {
      assertNotEquals(token, PasetoV2Local.encrypt(secretKey, nonce, payload ?: "", footer))
    } else {
      assertEquals(token, PasetoV2Local.encrypt(secretKey, nonce, payload ?: "", footer))
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
      token: String
  ) {
    val parsedToken = Token.parse(token)
    if (expectFail) {
      assertThrows<PasetoException> { PasetoV2Local.decrypt(secretKey, parsedToken) }
    } else {
      val (actualMessage, actualFooter) = PasetoV2Local.decrypt(secretKey, parsedToken)
      assertEquals(payload ?: "", actualMessage)
      assertEquals(footer, actualFooter)
    }
  }

  companion object {
    @JvmStatic
    fun testVectors(): List<Arguments> =
        TestVectors.read(Version.V2, Purpose.Local).map { vector ->
          Arguments.of(
              vector.name,
              vector.expectFail,
              vector.key(Version.V2),
              vector.nonce,
              vector.payload,
              vector.footer,
              vector.token)
        }
  }
}
