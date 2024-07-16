package com.bettermarks.paseto.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
 */
object PAE {
  private fun toLE64(n: Int): ByteArray {
    val unsigned = Integer.toUnsignedLong(n)
    val buffer: ByteBuffer = ByteBuffer.allocate(8)
    buffer.order(ByteOrder.LITTLE_ENDIAN)
    buffer.putLong(unsigned)
    return buffer.array()
  }

  fun encode(vararg pieces: ByteArray): ByteArray =
      ByteArrayOutputStream().use { bos ->
        bos.write(PAE.toLE64(pieces.size))
        for (piece in pieces) {
          bos.write(PAE.toLE64(piece.size))
          bos.write(piece)
        }
        bos.toByteArray()
      }
}
