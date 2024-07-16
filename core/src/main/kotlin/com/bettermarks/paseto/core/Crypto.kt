package com.bettermarks.paseto.core

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.DefaultBufferedBlockCipher
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.signers.PSSSigner
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.Pack

object Crypto {

  fun randomBytes(length: Int): ByteArray {
    val random = ByteArray(length)
    SecureRandom().nextBytes(random)
    return random
  }

  fun hmac384(key: ByteArray, message: ByteArray): ByteArray {
    val digest = SHA384Digest()
    val mac = HMac(digest)
    mac.init(KeyParameter(key))
    mac.update(message, 0, message.size)
    val out = ByteArray(digest.digestSize)
    mac.doFinal(out, 0)
    return out
  }

  fun hkdfSha384(key: ByteArray, salt: ByteArray?, info: ByteArray, size: Int): ByteArray {
    val hkdf = HKDFBytesGenerator(SHA384Digest())
    hkdf.init(HKDFParameters(key, salt, info))

    val out = ByteArray(size)
    hkdf.generateBytes(out, 0, size)
    return out
  }

  fun encryptAesCtr(key: ByteArray, nonce: ByteArray, message: ByteArray): ByteArray =
      Crypto.encryptDecryptAesCtr(true, key, nonce, message)

  fun decryptAesCtr(key: ByteArray, nonce: ByteArray, message: ByteArray): ByteArray =
      Crypto.encryptDecryptAesCtr(false, key, nonce, message)

  private fun encryptDecryptAesCtr(
      encryption: Boolean,
      key: ByteArray,
      nonce: ByteArray,
      message: ByteArray
  ): ByteArray {
    val cipher = DefaultBufferedBlockCipher(SICBlockCipher.newInstance(AESEngine.newInstance()))
    cipher.init(encryption, ParametersWithIV(KeyParameter(key), nonce))
    val out = ByteArray(cipher.getOutputSize(message.size))
    val len = cipher.processBytes(message, 0, message.size, out, 0)
    cipher.doFinal(out, len)
    return out
  }

  fun encryptXChaCha20Poly1305(
      message: ByteArray,
      aad: ByteArray,
      nonce: ByteArray,
      key: ByteArray
  ): ByteArray = Crypto.encryptDecryptXChaCha20Poly1305(true, message, aad, nonce, key)

  fun decryptXChaCha20Poly1305(
      message: ByteArray,
      aad: ByteArray,
      nonce: ByteArray,
      key: ByteArray
  ): ByteArray = Crypto.encryptDecryptXChaCha20Poly1305(false, message, aad, nonce, key)

  fun encryptDecryptXChaCha20Poly1305(
      encryption: Boolean,
      message: ByteArray,
      aad: ByteArray,
      nonce: ByteArray,
      key: ByteArray
  ): ByteArray {
    val xChaCha = Crypto.XChaCha20Engine()
    val subKey = Pack.intToLittleEndian(xChaCha.hChaChaDeriveSubKey(key, nonce))

    val keyParam = KeyParameter(subKey)
    val chaChaNonce = ByteArray(12)
    System.arraycopy(nonce, 16, chaChaNonce, 4, 8)

    val aead = ChaCha20Poly1305()

    aead.init(encryption, ParametersWithIV(keyParam, chaChaNonce))
    aead.processAADBytes(aad, 0, aad.size)
    val out = ByteArray(aead.getOutputSize(message.size))
    val len = aead.processBytes(message, 0, message.size, out, 0)
    aead.doFinal(out, len)
    return out
  }

  fun xchacha20(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
    val engine = Crypto.XChaCha20Engine()

    engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
    val out = ByteArray(message.size)

    engine.processBytes(message, 0, message.size, out, 0)

    return out
  }

  fun blake2b(size: Int, message: ByteArray, key: ByteArray): ByteArray {
    val digest = Blake2bDigest(key, size, null, null)
    val out = ByteArray(size)
    digest.update(message, 0, message.size)
    digest.doFinal(out, 0)
    return out
  }

  fun signED25519(
      sk: ByteArray,
      m: ByteArray,
  ): ByteArray {
    val params = PrivateKeyFactory.createKey(sk)
    val ed25519 = Ed25519Signer()
    ed25519.init(true, params)
    ed25519.update(m, 0, m.size)
    return ed25519.generateSignature()
  }

  fun verifyED25519(pk: ByteArray, m: ByteArray, sig: ByteArray): Boolean {
    val params: CipherParameters = PublicKeyFactory.createKey(pk)
    val ed25519 = Ed25519Signer()
    ed25519.init(false, params)
    ed25519.update(m, 0, m.size)
    return ed25519.verifySignature(sig)
  }

  fun signRsaPssSha384(privateKey: ByteArray, msg: ByteArray): ByteArray {
    val signer = PSSSigner(RSAEngine(), SHA384Digest(), SHA384Digest(), SHA384Digest().digestSize)

    val key = PrivateKeyFactory.createKey(privateKey) as RSAPrivateCrtKeyParameters
    if (key.modulus.bitLength() != 2048) throw PasetoException("RSA 2048 should be used")

    signer.init(true, key)
    signer.update(msg, 0, msg.size)
    return signer.generateSignature()
  }

  fun verifyRsaPssSha384(publicKey: ByteArray, msg: ByteArray, signature: ByteArray): Boolean {
    val signer = PSSSigner(RSAEngine(), SHA384Digest(), SHA384Digest(), SHA384Digest().digestSize)

    signer.init(false, PublicKeyFactory.createKey(publicKey))
    signer.update(msg, 0, msg.size)
    return signer.verifySignature(signature)
  }

  fun signECDSA(privateKey: ByteArray, msg: ByteArray): ByteArray {
    val digest = SHA384Digest()
    digest.update(msg, 0, msg.size)
    val digestOut = ByteArray(digest.digestSize)
    digest.doFinal(digestOut, 0)

    val signer = ECDSASigner(HMacDSAKCalculator(SHA384Digest()))

    val key = PrivateKeyFactory.createKey(privateKey)

    signer.init(true, key)
    val sig = signer.generateSignature(digestOut)
    val r = sig[0]
    val s = sig[1]

    return Crypto.toUnsignedByteArray(r, 48) + Crypto.toUnsignedByteArray(s, 48)
  }

  fun verifyECDSA(publicKey: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
    val digest = SHA384Digest()
    digest.update(msg, 0, msg.size)
    val digestOut = ByteArray(digest.digestSize)
    digest.doFinal(digestOut, 0)

    val signer = ECDSASigner(HMacDSAKCalculator(SHA384Digest()))

    val key = PublicKeyFactory.createKey(publicKey)

    signer.init(false, key)
    val r = BigInteger(1, sig.copyOfRange(0, 48))
    val s = BigInteger(1, sig.copyOfRange(48, 96))
    return signer.verifySignature(digestOut, r, s)
  }

  private fun toUnsignedByteArray(n: BigInteger, length: Int): ByteArray {
    var bs = BigIntegers.asUnsignedByteArray(n)
    if (bs.size < length) {
      val tmp = ByteArray(length)
      System.arraycopy(bs, 0, tmp, length - bs.size, bs.size)
      bs = tmp
    }
    return bs
  }

  /** Taken from dangling PR https://github.com/bcgit/bc-java/pull/957 */
  private class XChaCha20Engine : ChaChaEngine() {
    override fun getAlgorithmName(): String {
      return "XChaCha20"
    }

    override fun getNonceSize(): Int {
      return 24
    }

    override fun setKey(keyBytes: ByteArray, ivBytes: ByteArray) {
      requireNotNull(keyBytes) { "$algorithmName doesn't support re-init with null key" }

      check(keyBytes.size == 32) { "$algorithmName requires a 256 bit key" }

      // Derive sub key using the HChaCha algorithm and set copy it to the engine state
      val subKey = hChaChaDeriveSubKey(keyBytes, ivBytes)
      System.arraycopy(subKey, 0, engineState, 4, subKey.size)

      // Use last 64 bits of input IV as nonce for ChaCha20
      Pack.littleEndianToInt(ivBytes, 16, engineState, 14, 2)
    }

    fun hChaChaDeriveSubKey(keyBytes: ByteArray?, ivBytes: ByteArray?): IntArray {
      requireNotNull(keyBytes) { "HChaCha$rounds doesn't support null keys" }

      check(keyBytes.size == 32) { "HChaCha$rounds  requires a 256 bit key" }

      requireNotNull(ivBytes) { "HChaCha$rounds  needs a non-null IV" }

      require(ivBytes.size >= 16) { "HChaCha$rounds needs an at least 128 bit nonce" }

      // Set key for HChaCha20
      super.setKey(keyBytes, ivBytes)
      Pack.littleEndianToInt(ivBytes, 0, engineState, 12, 4)

      // Process engine state to generate ChaCha20 key
      val hchacha20Out = IntArray(engineState.size)
      chachaCore(20, engineState, hchacha20Out)

      // Take first and last 128 bits of output as the sub key
      val subkey = IntArray(8)
      System.arraycopy(hchacha20Out, 0, subkey, 0, 4)
      System.arraycopy(hchacha20Out, 12, subkey, 4, 4)

      // Remove addition in final round of chachaCore
      subkey[0] -= engineState[0]
      subkey[1] -= engineState[1]
      subkey[2] -= engineState[2]
      subkey[3] -= engineState[3]
      subkey[4] -= engineState[12]
      subkey[5] -= engineState[13]
      subkey[6] -= engineState[14]
      subkey[7] -= engineState[15]

      return subkey
    }
  }
}
