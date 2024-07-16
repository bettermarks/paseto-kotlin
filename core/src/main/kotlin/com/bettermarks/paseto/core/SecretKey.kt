package com.bettermarks.paseto.core

data class SecretKey(val version: Version, val material: ByteArray) {
  fun requireVersion(requiredVersion: Version) {
    if (version != requiredVersion)
        throw PasetoException("Key not valid for ${requiredVersion.version}")
  }

  fun requiredKeyLength(requiredLength: Int) {
    if (material.size < requiredLength)
        throw PasetoException("Key must have ${requiredLength} bytes")
  }
}
