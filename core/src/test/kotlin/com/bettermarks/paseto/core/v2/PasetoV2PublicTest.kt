package com.bettermarks.paseto.core.v2

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

class PasetoV2PublicTest {
  @OptIn(ExperimentalStdlibApi::class)
  @ParameterizedTest(name = "Sign {0}")
  @MethodSource("testVectors")
  fun sign(
      @Suppress("UNUSED_PARAMETER") name: String,
      expectFail: Boolean,
      @Suppress("UNUSED_PARAMETER") publicKey: PublicKey,
      privateKey: PrivateKey,
      payload: String?,
      footer: String,
      token: String
  ) {
    val actualToken = PasetoV2Public.sign(privateKey, TokenContent(payload ?: "", footer))

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
      token: String
  ) {
    val parsedToken = Token.parse(token)

    if (expectFail) {
      assertThrows<PasetoException> { PasetoV2Public.verify(publicKey, parsedToken) }
    } else {
      val (actualMessage, actualFooter) = PasetoV2Public.verify(publicKey, parsedToken)

      assertEquals(payload, actualMessage)
      assertEquals(footer, actualFooter)
    }
  }

  companion object {
    @JvmStatic
    fun testVectors(): List<Arguments> =
        TestVectors.read(Version.V2, Purpose.Public).map { vector ->
          Arguments.of(
              vector.name,
              vector.expectFail,
              vector.publicKey(Version.V2),
              vector.privateKey(Version.V2),
              vector.payload,
              vector.footer,
              vector.token)
        }
  }
}
