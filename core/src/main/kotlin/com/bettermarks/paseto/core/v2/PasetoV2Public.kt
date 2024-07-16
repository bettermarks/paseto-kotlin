package com.bettermarks.paseto.core.v2

import com.bettermarks.paseto.core.Crypto
import com.bettermarks.paseto.core.PAE
import com.bettermarks.paseto.core.PasetoException
import com.bettermarks.paseto.core.PrivateKey
import com.bettermarks.paseto.core.PublicKey
import com.bettermarks.paseto.core.Purpose
import com.bettermarks.paseto.core.Token
import com.bettermarks.paseto.core.TokenContent
import com.bettermarks.paseto.core.TokenHeader
import com.bettermarks.paseto.core.Version

object PasetoV2Public {
  private val tokenHeader = TokenHeader(Version.V2, Purpose.Public)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md#sign
   */
  fun sign(key: PrivateKey, content: TokenContent): String {
    key.requireVersion(Version.V2)

    val m2 =
        PAE.encode(
            tokenHeader.asBytes,
            content.message.toByteArray(Charsets.UTF_8),
            content.footer.toByteArray(Charsets.UTF_8))
    val signature = Crypto.signED25519(key.material, m2)

    return Token(
            tokenHeader, content.message.toByteArray(Charsets.UTF_8) + signature, content.footer)
        .toString()
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md#verify
   */
  fun verify(publicKey: PublicKey, token: Token): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    publicKey.requireVersion(Version.V2)

    // 3
    val sm: ByteArray = token.payload
    if (sm.size < 64) throw PasetoException("Payload too short")
    val signature = sm.copyOfRange(sm.size - 64, sm.size)
    val message = sm.copyOfRange(0, sm.size - 64)

    // 4
    val m2 = PAE.encode(token.header.asBytes, message, token.footer.toByteArray(Charsets.UTF_8))

    // 5
    if (!Crypto.verifyED25519(publicKey.material, m2, signature))
        throw PasetoException("Signature does not match")

    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }
}
