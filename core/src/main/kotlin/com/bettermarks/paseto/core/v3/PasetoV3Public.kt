package com.bettermarks.paseto.core.v3

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
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory

object PasetoV3Public {
  private val tokenHeader = TokenHeader(Version.V3, Purpose.Public)

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign
   */
  fun sign(key: PrivateKey, content: TokenContent, implicitAssertion: String): String {
    key.requireVersion(Version.V3)

    val pk = publicKeyFromPrivate(key)
    if (pk.size != 49) throw PasetoException("pk must be 49 bytes long")
    if (pk[0] != 2.toByte() && pk[0] != 3.toByte())
        throw PasetoException("pk must start with 0x2 or 0x3")

    val m2 =
        PAE.encode(
            pk,
            tokenHeader.asBytes,
            content.message.toByteArray(Charsets.UTF_8),
            content.footer.toByteArray(Charsets.UTF_8),
            implicitAssertion.toByteArray(Charsets.UTF_8))

    val signature = Crypto.signECDSA(key.material, m2)

    return Token(
            tokenHeader, content.message.toByteArray(Charsets.UTF_8) + signature, content.footer)
        .toString()
  }

  fun verify(publicKey: PublicKey, token: Token, implicitAssertion: String): TokenContent {
    if (token.header != tokenHeader)
        throw PasetoException("Invalid header (version/purpose does not match)")
    publicKey.requireVersion(Version.V3)

    // 3
    val sm = token.payload
    if (sm.size < 96) throw PasetoException("payload too short")
    val signature = sm.copyOfRange(sm.size - 96, sm.size)
    val message = sm.copyOfRange(0, sm.size - 96)

    // 4
    val pk = toCompressed(publicKey)
    val m2 =
        PAE.encode(
            pk,
            tokenHeader.asBytes,
            message,
            token.footer.toByteArray(Charsets.UTF_8),
            implicitAssertion.toByteArray(Charsets.UTF_8))

    if (!Crypto.verifyECDSA(publicKey.material, m2, signature))
        throw PasetoException("Signature does not match")

    return TokenContent(message.toString(Charsets.UTF_8), token.footer)
  }

  fun publicKeyFromPrivate(privateKey: PrivateKey): ByteArray {
    val ecPrivate = PrivateKeyFactory.createKey(privateKey.material) as ECPrivateKeyParameters
    val point = ecPrivate.parameters.g.multiply(ecPrivate.d)
    return point.getEncoded(true)
  }

  private fun toCompressed(key: PublicKey): ByteArray {
    val ecPublic = PublicKeyFactory.createKey(key.material) as ECPublicKeyParameters
    return ecPublic.q.getEncoded(true)
  }
}
