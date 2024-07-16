package com.bettermarks.paseto.core

import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(ExperimentalStdlibApi::class)
class PAETest {
  @Test
  fun pae() {
    assertEquals("0000000000000000", PAE.encode().toHexString())
    assertEquals(
        "01000000000000000000000000000000",
        PAE.encode("".toByteArray(Charsets.UTF_8)).toHexString())
    assertEquals(
        "020000000000000000000000000000000000000000000000",
        PAE.encode("".toByteArray(Charsets.UTF_8), "".toByteArray(Charsets.UTF_8)).toHexString())
    assertEquals(
        "0100000000000000070000000000000050617261676f6e",
        PAE.encode("Paragon".toByteArray(Charsets.UTF_8)).toHexString())
    assertEquals(
        "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
        PAE.encode("Paragon".toByteArray(Charsets.UTF_8), "Initiative".toByteArray(Charsets.UTF_8))
            .toHexString())
    assertEquals(
        "0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665",
        PAE.encode(
                "Paragon\n\u0000\u0000\u0000\u0000\u0000\u0000\u0000Initiative"
                    .toByteArray(Charsets.UTF_8))
            .toHexString())
  }
}
