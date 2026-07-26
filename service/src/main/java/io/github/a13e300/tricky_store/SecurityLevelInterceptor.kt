package io.github.a13e300.tricky_store

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.keystore.CertHack.KeyGenParameters
import io.github.a13e300.tricky_store.keystore.KeyDb
import io.github.a13e300.tricky_store.keystore.SoftwareOperation
import io.github.a13e300.tricky_store.keystore.SoftwareOperationBinder
import io.github.a13e300.tricky_store.keystore.Utils
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    init {
        // Expose the TEE binder so the KeyDb fallback path (companion) can set
        // iSecurityLevel on responses rebuilt after a process restart.
        if (level == 1) teeSecurityLevel = original
    }

    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val keys = ConcurrentHashMap<Key, Info>()
        private val nextOpId = AtomicLong(1L)

        @Volatile
        private var teeSecurityLevel: IKeystoreSecurityLevel? = null

        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? {
            // Fast path: in-memory cache
            keys[Key(uid, alias)]?.response?.let { return it }
            // 1.4.0+: fallback to KeyDb persistent storage
            val loaded = KeyDb.load(uid, alias) ?: return null
            val (kp, chain) = loaded
            // Build a minimal response so the caller can use it
            val response = KeyEntryResponse()
            val metadata = KeyMetadata()
            metadata.keySecurityLevel = 1 // TEE
            Utils.putCertificateChain(metadata, chain.toTypedArray())
            val d = KeyDescriptor()
            // Domain.APP = 0 (not SELINUX=2). For APP domain, nspace is the calling uid.
            d.domain = Domain.APP
            d.nspace = uid.toLong()
            d.alias = alias
            metadata.key = d
            response.metadata = metadata
            // Restore the security-level binder so the app can createOperation on it
            response.iSecurityLevel = teeSecurityLevel
            // Cache for next time
            keys[Key(uid, alias)] = Info(kp, response)
            return response
        }

        /** 1.4.0+: Build KeyDescriptor list for listEntries interception. */
        fun getGeneratedKeyDescriptors(uid: Int, startPastAlias: String? = null): List<KeyDescriptor> {
            val result = mutableListOf<KeyDescriptor>()
            for ((key, info) in keys) {
                if (key.uid != uid) continue
                if (startPastAlias != null && key.alias <= startPastAlias) continue
                val d = KeyDescriptor()
                d.domain = Domain.APP
                d.nspace = info.response.metadata.key?.nspace ?: uid.toLong()
                d.alias = key.alias
                result.add(d)
            }
            // Also surface keys that only exist on disk (process restart)
            for (alias in KeyDb.listAliases(uid)) {
                if (result.any { it.alias == alias }) continue
                if (startPastAlias != null && alias <= startPastAlias) continue
                val d = KeyDescriptor()
                d.domain = Domain.APP
                d.nspace = uid.toLong()
                d.alias = alias
                result.add(d)
            }
            return result.sortedBy { it.alias }
        }

        /** 1.4.0+: Remove generated key from memory + KeyDb. */
        fun removeKey(uid: Int, alias: String) {
            keys.remove(Key(uid, alias))
            KeyDb.delete(uid, alias)
        }
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (code == generateKeyTransaction && Config.needGenerate(callingUid)) {
            Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                // val aFlags = data.readInt()
                // val entropy = data.createByteArray()
                val kgp = KeyGenParameters(params)
                if (kgp.attestationChallenge != null) {
                    if (attestationKeyDescriptor != null) {
                        Logger.e("warn: attestation key not supported now")
                    } else {
                        val pair = CertHack.generateKeyPair(callingUid, keyDescriptor, kgp)
                            ?: return@runCatching
                        val response = buildResponse(pair.second, kgp, keyDescriptor, callingUid)
                        keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                        // 1.4.0+: persist to key_db
                        KeyDb.save(callingUid, keyDescriptor.alias, pair.first, pair.second)
                        val p = Parcel.obtain()
                        p.writeNoException()
                        p.writeTypedObject(response.metadata, 0)
                        return OverrideReply(0, p)
                    }
                }
            }.onFailure {
                Logger.e("parse key gen request", it)
            }
        } else if (code == createOperationTransaction) {
            return handleCreateOperation(callingUid, data)
        }
        return Skip
    }

    private fun handleCreateOperation(callingUid: Int, data: Parcel): Result {
        kotlin.runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            @Suppress("UNUSED_VARIABLE")
            val forced = data.readBoolean()

            // Prefer memory cache; fall back to KeyDb after process restart
            val info = keys[Key(callingUid, keyDescriptor.alias)]
                ?: getKeyResponse(callingUid, keyDescriptor.alias)?.let {
                    keys[Key(callingUid, keyDescriptor.alias)]
                }
                ?: return@runCatching // not a generated key, pass through

            val opPurpose = params.firstOrNull { it.tag == Tag.PURPOSE }?.value?.getKeyPurpose()
                ?: KeyPurpose.SIGN

            val txId = nextOpId.getAndIncrement()
            Logger.i("createOperation uid=$callingUid alias=${keyDescriptor.alias} purpose=$opPurpose tx=$txId")

            val swParams = SoftwareOperation.KeyMintParams(params)
            val op = SoftwareOperation(
                keyPair = info.keyPair,
                params = swParams,
                opPurpose = opPurpose,
                txId = txId,
            )

            val response = CreateOperationResponse()
            response.iOperation = SoftwareOperationBinder(op)
            // No auth challenge for software-generated keys without auth
            response.operationChallenge = null

            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(response, 0)
            return OverrideReply(0, p)
        }.onFailure {
            Logger.e("handleCreateOperation failed", it)
        }
        return Skip
    }

    private fun buildResponse(
        chain: List<Certificate>,
        params: KeyGenParameters,
        descriptor: KeyDescriptor,
        uid: Int
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        Utils.putCertificateChain(metadata, chain.toTypedArray<Certificate>())
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        d.alias = descriptor.alias
        d.blob = descriptor.blob
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true) // TODO: copy
        a.securityLevel = level
        authorizations.add(a)
        // 1.4.0+: Tag.ORIGIN = GENERATED (0)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ORIGIN
        a.keyParameter.value = KeyParameterValue.integer(0)
        a.securityLevel = level
        authorizations.add(a)
        // OS_VERSION
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.OS_VERSION
        a.keyParameter.value = KeyParameterValue.integer(osVersion)
        a.securityLevel = level
        authorizations.add(a)
        // OS_PATCHLEVEL
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.OS_PATCHLEVEL
        a.keyParameter.value = KeyParameterValue.integer(getOsPatchLevel(uid))
        a.securityLevel = level
        authorizations.add(a)
        // VENDOR_PATCHLEVEL
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.VENDOR_PATCHLEVEL
        a.keyParameter.value = KeyParameterValue.integer(getVendorPatchLevel(uid))
        a.securityLevel = level
        authorizations.add(a)
        // BOOT_PATCHLEVEL
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.BOOT_PATCHLEVEL
        a.keyParameter.value = KeyParameterValue.integer(getBootPatchLevel(uid))
        a.securityLevel = level
        authorizations.add(a)
        // CREATION_DATETIME
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.CREATION_DATETIME
        a.keyParameter.value = KeyParameterValue.dateTime(System.currentTimeMillis())
        a.securityLevel = level
        authorizations.add(a)
        // USER_ID — Android user id (uid / 100000), not keystore nspace
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.USER_ID
        a.keyParameter.value = KeyParameterValue.integer(uid / 100000)
        a.securityLevel = level
        authorizations.add(a)
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
