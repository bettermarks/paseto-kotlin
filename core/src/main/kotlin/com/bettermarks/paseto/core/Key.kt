package com.bettermarks.paseto.core

sealed abstract class Key(val version: Version, val purpose: Purpose, val id: String?) {
  fun requireVersion(requiredVersion: Version) {
    if (version != requiredVersion)
        throw PasetoException("Key not valid for ${requiredVersion.version}")
  }
}

sealed interface SigningKey {
  val id: String?
  val version: Version
  val purpose: Purpose
}

sealed interface VerificationKey

class SecretKey(version: Version, val material: ByteArray, id: String? = null) :
    Key(version, Purpose.Local, id), SigningKey, VerificationKey {
  fun requiredKeyLength(requiredLength: Int) {
    if (material.size < requiredLength) throw PasetoException("Key must have $requiredLength bytes")
  }
}

class PublicKey(version: Version, val material: ByteArray, id: String? = null) :
    Key(version, Purpose.Public, id), VerificationKey

class PrivateKey(version: Version, val material: ByteArray, id: String? = null) :
    Key(version, Purpose.Public, id), SigningKey
