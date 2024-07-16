package com.bettermarks.paseto.core.v2

import com.bettermarks.paseto.core.Crypto
import com.bettermarks.paseto.core.PAE
import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.SecretKey
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.TokenHeader
import com.bettermarks.paseto.core.Version

object PasetoV2Local {
  private val tokenHeader = TokenHeader(Version.V2, Purpose.Local)

  fun encrypt(key: SecretKey, content: TokenContent): String =
      encrypt(key, Crypto.randomBytes(24), content.message, content.footer)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
   */
  fun encrypt(key: SecretKey, randomKey: ByteArray, message: String, footer: String): String {
    key.requireVersion(Version.V2)
    key.requiredKeyLength(32)

    // 3
    val nonce = Crypto.blake2b(24, message.toByteArray(Charsets.UTF_8), randomKey)

    // 4
    val preAuth = PAE.encode(tokenHeader.asBytes, nonce, footer.toByteArray(Charsets.UTF_8))

    // 5
    val cipherText =
        Crypto.encryptXChaCha20Poly1305(
            message.toByteArray(Charsets.UTF_8), preAuth, nonce, key.material)

    // 6
    return Token(tokenHeader, nonce + cipherText, footer).toString()
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt
   */
  fun decrypt(key: SecretKey, token: Token): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    key.requireVersion(Version.V2)
    key.requiredKeyLength(32)

    // 3
    val ct = token.payload
    if (ct.size < 24) throw PasetoException("Payload too short")
    val nonce = ct.copyOfRange(0, 24)
    val c = ct.copyOfRange(24, ct.size)

    // 4
    val preAuth = PAE.encode(tokenHeader.asBytes, nonce, token.footer.toByteArray(Charsets.UTF_8))

    // 5
    val message = Crypto.decryptXChaCha20Poly1305(c, preAuth, nonce, key.material)
    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }
}
