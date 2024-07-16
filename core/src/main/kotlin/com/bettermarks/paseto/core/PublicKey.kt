package com.bettermarks.paseto.core

data class PublicKey(val version: Version, val material: ByteArray) {
  fun requireVersion(requiredVersion: Version) {
    if (version != requiredVersion)
        throw PasetoException("PublicKey not valid for ${requiredVersion.version}")
  }
}
