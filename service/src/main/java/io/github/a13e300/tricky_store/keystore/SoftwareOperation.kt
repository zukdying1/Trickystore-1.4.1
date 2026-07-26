package io.github.a13e300.tricky_store.keystore

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import io.github.a13e300.tricky_store.Logger
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher

/**
 * 1.4.0: Software-based cryptographic operations for generated keys.
 * Maps KeyMint parameters to JCA algorithms (aligned with TEESimulator SoftwareOperation).
 */
class SoftwareOperation(
    private val keyPair: KeyPair,
    private val params: KeyMintParams,
    private val opPurpose: Int,
    private val txId: Long,
) {
    private sealed interface CryptoPrimitive {
        fun update(data: ByteArray?): ByteArray?
        fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
        fun abort()
    }

    private object JcaAlgorithmMapper {
        fun mapSignatureAlgorithm(params: KeyMintParams): String {
            val digest = when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                Digest.SHA1 -> "SHA1"
                Digest.SHA_2_224 -> "SHA224"
                else -> "NONE"
            }
            val keyAlgo = when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported signature algorithm: ${params.algorithm}")
            }
            // JCA expects "SHA256withECDSA" / "SHA256withRSA"
            return if (digest == "NONE") "NONEwith$keyAlgo" else "${digest}with$keyAlgo"
        }

        fun mapCipherAlgorithm(params: KeyMintParams): String {
            val keyAlgo = when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else -> throw IllegalArgumentException("Unsupported cipher algorithm: ${params.algorithm}")
            }
            val blockMode = when (params.blockMode.firstOrNull()) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.GCM -> "GCM"
                else -> "ECB"
            }
            val padding = when (params.padding.firstOrNull()) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding"
            }
            return "$keyAlgo/$blockMode/$padding"
        }
    }

    private class Signer(keyPair: KeyPair, params: KeyMintParams) : CryptoPrimitive {
        private val signature: Signature =
            Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
                initSign(keyPair.private)
            }

        override fun update(data: ByteArray?): ByteArray? {
            if (data != null) signature.update(data)
            return null
        }

        override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
            if (data != null) update(data)
            return this.signature.sign()
        }

        override fun abort() {}
    }

    private class Verifier(keyPair: KeyPair, params: KeyMintParams) : CryptoPrimitive {
        private val signature: Signature =
            Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
                initVerify(keyPair.public)
            }

        override fun update(data: ByteArray?): ByteArray? {
            if (data != null) signature.update(data)
            return null
        }

        override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
            if (data != null) update(data)
            if (signature == null) throw SignatureException("Signature to verify is null")
            if (!this.signature.verify(signature)) {
                throw SignatureException("Signature verification failed")
            }
            return null
        }

        override fun abort() {}
    }

    private class CipherPrimitive(
        keyPair: KeyPair,
        params: KeyMintParams,
        private val opMode: Int,
    ) : CryptoPrimitive {
        private val cipher: Cipher =
            Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
                val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair.public else keyPair.private
                init(opMode, key)
            }

        override fun update(data: ByteArray?): ByteArray? =
            if (data != null) cipher.update(data) else null

        override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
            if (data != null) cipher.doFinal(data) else cipher.doFinal()

        override fun abort() {}
    }

    private val primitive: CryptoPrimitive = when (opPurpose) {
        KeyPurpose.SIGN -> Signer(keyPair, params)
        KeyPurpose.VERIFY -> Verifier(keyPair, params)
        KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
        KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
        else -> throw UnsupportedOperationException("Unsupported operation purpose: $opPurpose")
    }

    fun update(data: ByteArray?): ByteArray? {
        try {
            return primitive.update(data)
        } catch (e: Exception) {
            Logger.e("SoftwareOp tx=$txId update failed", e)
            throw e
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        try {
            val result = primitive.finish(data, signature)
            Logger.d("SoftwareOp tx=$txId finished")
            return result
        } catch (e: Exception) {
            Logger.e("SoftwareOp tx=$txId finish failed", e)
            throw e
        }
    }

    fun abort() {
        primitive.abort()
        Logger.d("SoftwareOp tx=$txId aborted")
    }

    fun updateAad(aad: ByteArray?) {
        // AAD only applies to AEAD ciphers; generated EC/RSA keys ignore it.
        if (aad != null) {
            Logger.d("SoftwareOp tx=$txId updateAad ignored (len=${aad.size})")
        }
    }

    data class KeyMintParams(
        val algorithm: Int = 0,
        val keySize: Int = 0,
        val ecCurve: Int? = null,
        val digest: List<Int> = emptyList(),
        val padding: List<Int> = emptyList(),
        val blockMode: List<Int> = emptyList(),
        val purpose: List<Int> = emptyList(),
    ) {
        constructor(params: Array<KeyParameter>) : this(
            // Use getters (not static tag discriminators named algorithm/digest/...)
            algorithm = params.findTag(Tag.ALGORITHM)?.value?.getAlgorithm() ?: 0,
            keySize = params.findTag(Tag.KEY_SIZE)?.value?.getInteger() ?: 0,
            ecCurve = params.findTag(Tag.EC_CURVE)?.value?.getEcCurve(),
            digest = params.filter { it.tag == Tag.DIGEST }.map { it.value.getDigest() },
            padding = params.filter { it.tag == Tag.PADDING }.map { it.value.getPaddingMode() },
            blockMode = params.filter { it.tag == Tag.BLOCK_MODE }.map { it.value.getBlockMode() },
            purpose = params.filter { it.tag == Tag.PURPOSE }.map { it.value.getKeyPurpose() },
        )
    }

    private fun Array<KeyParameter>.findTag(tag: Int): KeyParameter? =
        firstOrNull { it.tag == tag }
}

/** Binder interface for SoftwareOperation. */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) = operation.updateAad(aadInput)

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? = operation.update(input)

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? =
        operation.finish(input, signature)

    @Throws(RemoteException::class)
    override fun abort() = operation.abort()
}
