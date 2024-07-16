package com.bettermarks.paseto.core

import java.util.*

data class TokenHeader(val version: Version, val purpose: Purpose) {
  val asString
    get() = "${version.version}.${purpose.purpose}."

  val asBytes
    get() = asString.toByteArray(Charsets.UTF_8)
}

data class TokenContent(val message: String, val footer: String)

class Token(val header: TokenHeader, val payload: ByteArray, val footer: String) {
  override fun toString() =
      if (footer.isEmpty()) "${header.asString}${Token.Companion.encoder.encodeToString(payload)}"
      else
          "${header.asString}${Token.Companion.encoder.encodeToString(payload)}.${Token.Companion.encoder.encodeToString(footer.toByteArray(Charsets.UTF_8))}"

  companion object {
    val encoder = Base64.getUrlEncoder().withoutPadding()
    val decoder = Base64.getUrlDecoder()

    fun parse(token: String): Token {
      val parts = token.split('.')
      if (parts.size < 3 || parts.size > 4) throw PasetoException("Invalid token format")
      val version =
          Version.Companion.byName[parts[0]] ?: throw PasetoException("Invalid paseto version")
      val purpose =
          Purpose.Companion.byName[parts[1]] ?: throw PasetoException("Invalid paseto purpose")
      val payload = Token.Companion.decoder.decode(parts[2])
      val footer =
          if (parts.size == 4) Token.Companion.decoder.decode(parts[3]).toString(Charsets.UTF_8)
          else ""

      return Token(TokenHeader(version, purpose), payload, footer)
    }
  }
}
