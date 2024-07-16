package com.bettermarks.paseto.core.v3

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

object PasetoV3Local {
  private val tokenHeader = TokenHeader(Version.V3, Purpose.Local)

  fun encrypt(key: SecretKey, content: TokenContent, implicitAssertion: String): String =
      encrypt(key, Crypto.randomBytes(32), content.message, content.footer, implicitAssertion)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#encrypt
   */
  fun encrypt(
      key: SecretKey,
      nonce: ByteArray,
      message: String,
      footer: String,
      implicitAssertion: String
  ): String {
    key.requireVersion(Version.V3)
    key.requiredKeyLength(32)

    // 4
    val tmp = encryptionKey(key, nonce)
    val ek = tmp.copyOfRange(0, 32)
    val n2 = tmp.copyOfRange(32, 48)
    val ak = authenticationKey(key, nonce)

    // 5
    val cipherText = Crypto.encryptAesCtr(ek, n2, message.toByteArray(Charsets.UTF_8))

    // 6
    val preAuth =
        PAE.encode(
            tokenHeader.asBytes,
            nonce,
            cipherText,
            footer.toByteArray(Charsets.UTF_8),
            implicitAssertion.toByteArray(Charsets.UTF_8))

    // 7
    val t: ByteArray = Crypto.hmac384(ak, preAuth)

    // 8
    return Token(tokenHeader, nonce + cipherText + t, footer).toString()
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt
   */
  fun decrypt(key: SecretKey, token: Token, implicitAssertion: String): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    key.requireVersion(Version.V3)
    key.requiredKeyLength(32)

    // 4
    val ct = token.payload
    if (ct.size < 32 + 49) throw PasetoException("payload too short")
    val nonce = ct.copyOfRange(0, 32)
    val t = ct.copyOfRange(ct.size - 48, ct.size)
    val c = ct.copyOfRange(32, ct.size - 48)

    // 5
    val tmp = encryptionKey(key, nonce)
    val ek = tmp.copyOfRange(0, 32)
    val n2 = tmp.copyOfRange(32, 48)
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
    val t2: ByteArray = Crypto.hmac384(ak, preAuth)

    // 8
    if (!MessageDigest.isEqual(t, t2)) throw PasetoException("HMAC verification failed")

    val message: ByteArray = Crypto.decryptAesCtr(ek, n2, c)
    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }

  private fun encryptionKey(key: SecretKey, nonce: ByteArray) =
      Crypto.hkdfSha384(
          key.material, null, "paseto-encryption-key".toByteArray(Charsets.UTF_8) + nonce, 48)

  private fun authenticationKey(key: SecretKey, nonce: ByteArray) =
      Crypto.hkdfSha384(
          key.material, null, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8) + nonce, 48)
}
