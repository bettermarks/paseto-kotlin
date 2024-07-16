package com.bettermarks.paseto.core.v4

import com.bettermarks.paseto.core.Crypto
import com.bettermarks.paseto.core.PAE
import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.SecretKey
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.TokenHeader
import com.bettermarks.paseto.core.Version
import java.security.MessageDigest

object PasetoV4Local {
  private val tokenHeader = TokenHeader(Version.V4, Purpose.Local)

  fun encrypt(key: SecretKey, content: TokenContent, implicitAssertion: String): String =
      encrypt(key, Crypto.randomBytes(32), content.message, content.footer, implicitAssertion)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt
   */
  fun encrypt(
      key: SecretKey,
      nonce: ByteArray,
      message: String,
      footer: String,
      implicitAssertion: String
  ): String {
    key.requireVersion(Version.V4)
    key.requiredKeyLength(32)

    // 4
    val tmp = encryptionKey(key, nonce)
    val ek = tmp.copyOfRange(0, 32)
    val n2 = tmp.copyOfRange(32, 56)
    val ak = authenticationKey(key, nonce)

    // 5
    val c = Crypto.xchacha20(message.toByteArray(Charsets.UTF_8), n2, ek)

    // 6
    val preAuth =
        PAE.encode(
            tokenHeader.asBytes,
            nonce,
            c,
            footer.toByteArray(Charsets.UTF_8),
            implicitAssertion.toByteArray(Charsets.UTF_8))

    // 7
    val t = Crypto.blake2b(32, preAuth, ak)

    // 8
    return Token(tokenHeader, nonce + c + t, footer).toString()
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt
   */
  fun decrypt(key: SecretKey, token: Token, implicitAssertion: String): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    key.requireVersion(Version.V4)
    key.requiredKeyLength(32)

    // 4
    val nct = token.payload
    if (nct.size < 64) throw PasetoException("payload too short")
    val nonce = nct.copyOfRange(0, 32)
    val t = nct.copyOfRange(nct.size - 32, nct.size)
    val c = nct.copyOfRange(32, nct.size - 32)

    // 5
    val tmp = encryptionKey(key, nonce)
    val ek = tmp.copyOfRange(0, 32)
    val n2 = tmp.copyOfRange(32, 56)
    val ak = authenticationKey(key, nonce)

    // 6
    val preAuth =
        PAE.encode(
            token.header.asBytes,
            nonce,
            c,
            token.footer.toByteArray(Charsets.UTF_8),
            implicitAssertion.toByteArray(Charsets.UTF_8))

    // 7
    val t2 = Crypto.blake2b(32, preAuth, ak)

    // 8
    if (!MessageDigest.isEqual(t, t2)) throw PasetoException("HMAC verification failed")

    val message: ByteArray = Crypto.xchacha20(c, n2, ek)
    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }

  private fun encryptionKey(key: SecretKey, nonce: ByteArray): ByteArray {
    return Crypto.blake2b(
        56, "paseto-encryption-key".toByteArray(Charsets.UTF_8) + nonce, key.material)
  }

  private fun authenticationKey(key: SecretKey, nonce: ByteArray): ByteArray {
    return Crypto.blake2b(
        32, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8) + nonce, key.material)
  }
}
