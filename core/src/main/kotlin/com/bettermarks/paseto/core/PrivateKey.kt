package com.bettermarks.paseto.core

data class PrivateKey(val version: Version, val material: ByteArray) {
  fun requireVersion(requiredVersion: Version) {
    if (version != requiredVersion)
        throw PasetoException("PrivateKey not valid for ${requiredVersion.version}")
  }
}
