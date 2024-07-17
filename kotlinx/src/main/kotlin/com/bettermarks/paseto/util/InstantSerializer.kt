package com.bettermarks.paseto.util

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object InstantSerializer : KSerializer<Instant> {
  override val descriptor = PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)

  override fun deserialize(decoder: Decoder): Instant {
    val strValue = decoder.decodeString()

    return if (strValue.endsWith("Z")) {
      Instant.parse(strValue)
    } else {
      LocalDateTime.parse(strValue).toInstant(ZoneOffset.UTC)
    }
  }

  override fun serialize(
      encoder: Encoder,
      value: Instant,
  ) = encoder.encodeString(value.toString())
}
