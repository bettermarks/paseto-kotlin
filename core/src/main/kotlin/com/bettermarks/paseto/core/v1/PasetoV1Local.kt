package com.bettermarks.paseto.core.v1

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

object PasetoV1Local {
  private val tokenHeader = TokenHeader(Version.V1, Purpose.Local)

  fun encrypt(key: SecretKey, content: TokenContent): String =
      encrypt(key, Crypto.randomBytes(32), content.message, content.footer)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#encrypt
   */
  fun encrypt(key: SecretKey, randomKey: ByteArray, message: String, footer: String): String {
    key.requireVersion(Version.V1)
    key.requiredKeyLength(32)

    // 3 -
    // https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#getnonce
    val nonce = Crypto.hmac384(randomKey, message.toByteArray(Charsets.UTF_8)).copyOfRange(0, 32)

    // 4
    val ek = encryptionKey(key, nonce)
    val ak = authenticationKey(key, nonce)

    // 5
    val cipherText =
        Crypto.encryptAesCtr(ek, nonce.copyOfRange(16, 32), message.toByteArray(Charsets.UTF_8))

    // 6
    val preAuth =
        PAE.encode(tokenHeader.asBytes, nonce, cipherText, footer.toByteArray(Charsets.UTF_8))

    // 7
    val t = Crypto.hmac384(ak, preAuth)

    // 8
    return Token(tokenHeader, nonce + cipherText + t, footer).toString()
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt
   */
  fun decrypt(key: SecretKey, token: Token): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    key.requireVersion(Version.V1)
    key.requiredKeyLength(32)

    // 3
    val ct = token.payload
    if (ct.size < 32 + 48) throw PasetoException("Payload too short")
    val nonce = ct.copyOfRange(0, 32)
    val t = ct.copyOfRange(ct.size - 48, ct.size)
    val c = ct.copyOfRange(32, ct.size - 48)

    // 4
    val ek = encryptionKey(key, nonce)
    val ak = authenticationKey(key, nonce)

    // 5
    val preAuth =
        PAE.encode(token.header.asBytes, nonce, c, token.footer.toByteArray(Charsets.UTF_8))

    // 6
    val t2 = Crypto.hmac384(ak, preAuth)

    // 7
    if (!MessageDigest.isEqual(t, t2)) throw PasetoException("HMAC verification failed")

    // 8
    val message = Crypto.decryptAesCtr(ek, nonce.copyOfRange(16, 32), c)
    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }

  private fun encryptionKey(key: SecretKey, nonce: ByteArray): ByteArray =
      Crypto.hkdfSha384(
          key.material,
          nonce.copyOfRange(0, 16),
          "paseto-encryption-key".toByteArray(Charsets.UTF_8),
          32)

  private fun authenticationKey(key: SecretKey, nonce: ByteArray): ByteArray =
      Crypto.hkdfSha384(
          key.material,
          nonce.copyOfRange(0, 16),
          "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8),
          32)
}
