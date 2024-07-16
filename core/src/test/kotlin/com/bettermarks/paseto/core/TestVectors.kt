package com.bettermarks.paseto.core

import java.io.StringReader
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.encoders.Hex

@Serializable
data class TestVector(
    val name: String,
    @SerialName("expect-fail") val expectFail: Boolean,
    val payload: String? = null,
    val footer: String,
    val token: String,
    @SerialName("implicit-assertion") val implicitAssertion: String,
    @SerialName("key") val keyHex: String? = null,
    @SerialName("nonce") val nonceHex: String? = null,
    @SerialName("public-key") val publicKeyV1: String? = null,
    @SerialName("secret-key") val privateKeyV1: String? = null,
    @SerialName("public-key-pem") val publicKeyPem: String? = null,
    @SerialName("secret-key-pem") val privateKeyPem: String? = null
) {
  fun key(version: Version) = keyHex?.let { SecretKey(version, Hex.decode(it)) }

  val nonce
    get() = nonceHex?.let { Hex.decode(it) }

  fun publicKey(version: Version) =
      (publicKeyPem ?: publicKeyV1)?.let { PublicKey(version, readPublicPem(it)) }

  fun privateKey(version: Version) =
      (privateKeyPem ?: privateKeyV1)?.let { PrivateKey(version, readPrivatePem(it)) }

  companion object {
    fun readPrivatePem(pem: String): ByteArray =
        PEMParser(StringReader(pem)).use { parser ->
          val obj = parser.readObject()
          if (obj is PEMKeyPair) JcaPEMKeyConverter().getKeyPair(obj).private.encoded
          else if (obj is PrivateKeyInfo) obj.encoded
          else throw RuntimeException("Unknown PEM object ${obj::class.java}")
        }
  }

  fun readPublicPem(pem: String): ByteArray =
      PEMParser(StringReader(pem)).use { parser ->
        val obj = parser.readObject()
        if (obj is SubjectPublicKeyInfo) JcaPEMKeyConverter().getPublicKey(obj).encoded
        else throw RuntimeException("Unknown PEM object ${obj::class.java}")
      }
}

@Serializable
data class TestVectors(val name: String, val tests: List<TestVector>) {
  companion object {
    val json = Json { ignoreUnknownKeys = true }

    @OptIn(ExperimentalSerializationApi::class)
    fun read(version: Version, purpose: Purpose): List<TestVector> =
        TestVectors::class
            .java
            .classLoader
            .getResourceAsStream("test-vectors/${version.version}.json")
            .use { input ->
              json.decodeFromStream<TestVectors>(input!!).tests.filter { vector ->
                (purpose == Purpose.Local && vector.keyHex != null) ||
                    (purpose == Purpose.Public && vector.keyHex == null)
              }
            }
  }
}
