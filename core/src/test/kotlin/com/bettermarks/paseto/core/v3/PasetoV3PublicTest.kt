package com.bettermarks.paseto.core.v3

import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.PrivateKey
import com.bettermarks.paseto.core.PublicKey
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.TestVectors
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.Version
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class PasetoV3PublicTest {
  @ParameterizedTest(name = "SignVerify {0}")
  @MethodSource("testVectors")
  fun signVerify(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      publicKey: PublicKey,
      privateKey: PrivateKey,
      payload: String?,
      footer: String,
      token: String,
      implicitAssertion: String,
  ) {
    val actualToken =
        PasetoV3Public.sign(privateKey, TokenContent(payload ?: "", footer), implicitAssertion)
    val (actualMessage, actualFooter) =
        PasetoV3Public.verify(publicKey, Token.parse(actualToken), implicitAssertion)

    assertEquals(payload ?: "", actualMessage)
    assertEquals(footer, actualFooter)

    if (expectFail)
        assertThrows<PasetoException> {
          PasetoV3Public.verify(publicKey, Token.parse(token), implicitAssertion)
        }
    else {
      val (message, tokenFooter) =
          PasetoV3Public.verify(publicKey, Token.parse(token), implicitAssertion)

      assertEquals(payload ?: "", message)
      assertEquals(footer, tokenFooter)
    }
  }

  companion object {
    @JvmStatic
    fun testVectors(): List<Arguments> =
        TestVectors.read(Version.V3, Purpose.Public).map { vector ->
          Arguments.of(
              vector.name,
              vector.expectFail,
              vector.publicKey(Version.V3),
              vector.privateKey(Version.V3),
              vector.payload,
              vector.footer,
              vector.token,
              vector.implicitAssertion)
        }
  }
}
