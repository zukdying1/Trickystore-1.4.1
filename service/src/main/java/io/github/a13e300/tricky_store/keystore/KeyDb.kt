package io.github.a13e300.tricky_store.keystore

import android.util.Base64
import io.github.a13e300.tricky_store.Config
import io.github.a13e300.tricky_store.Logger
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import java.io.File
import java.io.StringWriter
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec

/**
 * 1.4.0 persistent storage for software-generated keys.
 * SECURITY.md: stored under /data/adb/tricky_store/key_db (root-only).
 *
 * Layout (simple, portable — avoids sqlite dependency on device):
 *   key_db/<uid>/<alias_b64>/private.pem
 *   key_db/<uid>/<alias_b64>/public.der
 *   key_db/<uid>/<alias_b64>/chain.pem
 *
 * A future drop-in can replace this with SQLite without changing call sites.
 */
object KeyDb {
    private val cf: CertificateFactory = CertificateFactory.getInstance("X.509")

    private fun dir(uid: Int, alias: String): File {
        val safe = Base64.encodeToString(
            alias.toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        return File(Config.keyDbDir, "$uid/$safe")
    }

    fun save(uid: Int, alias: String, keyPair: KeyPair, chain: List<Certificate>) = runCatching {
        val d = dir(uid, alias)
        d.mkdirs()
        // private key PKCS#8 PEM
        StringWriter().use { sw ->
            JcaPEMWriter(sw).use { pw ->
                pw.writeObject(JcaPKCS8Generator(keyPair.private, null))
            }
            File(d, "private.pem").writeText(sw.toString())
        }
        File(d, "public.der").writeBytes(keyPair.public.encoded)
        // chain PEMs concatenated
        val chainPem = buildString {
            chain.forEach { c ->
                append("-----BEGIN CERTIFICATE-----\n")
                append(
                    Base64.encodeToString(c.encoded, Base64.DEFAULT).trim()
                )
                append("\n-----END CERTIFICATE-----\n")
            }
        }
        File(d, "chain.pem").writeText(chainPem)
        File(d, "meta.txt").writeText("uid=$uid\nalias=$alias\nts=${System.currentTimeMillis()}\n")
        Logger.d("KeyDb saved uid=$uid alias=$alias")
    }.onFailure { Logger.e("KeyDb.save failed", it) }

    fun load(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? = runCatching {
        val d = dir(uid, alias)
        val privFile = File(d, "private.pem")
        val pubFile = File(d, "public.der")
        val chainFile = File(d, "chain.pem")
        if (!privFile.exists() || !pubFile.exists() || !chainFile.exists()) return null

        val privateKey = parsePrivatePem(privFile.readText())
        val publicKey = parsePublicDer(pubFile.readBytes(), privateKey.algorithm)
        val chain = parseCertChainPem(chainFile.readText())
        KeyPair(publicKey, privateKey) to chain
    }.onFailure {
        Logger.e("KeyDb.load failed uid=$uid alias=$alias", it)
    }.getOrNull()

    fun delete(uid: Int, alias: String) = runCatching {
        val d = dir(uid, alias)
        if (d.exists()) d.deleteRecursively()
    }

    /** List aliases persisted for a uid (decoded from base64 dir names). */
    fun listAliases(uid: Int): List<String> = runCatching {
        val uidDir = File(Config.keyDbDir, uid.toString())
        if (!uidDir.isDirectory) return emptyList()
        uidDir.listFiles()?.mapNotNull { f ->
            if (!f.isDirectory) return@mapNotNull null
            // require a complete entry
            if (!File(f, "private.pem").exists()) return@mapNotNull null
            try {
                String(
                    Base64.decode(
                        f.name,
                        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                    ),
                    Charsets.UTF_8
                )
            } catch (_: Throwable) {
                null
            }
        }?.sorted() ?: emptyList()
    }.getOrDefault(emptyList())

    fun clearAll() = runCatching {
        Config.keyDbDir.listFiles()?.forEach { it.deleteRecursively() }
    }

    private fun parsePrivatePem(pem: String): PrivateKey {
        // strip headers
        val b64 = pem.lines().filter { !it.startsWith("-----") && it.isNotBlank() }.joinToString("")
        val der = Base64.decode(b64, Base64.DEFAULT)
        val info = PrivateKeyInfo.getInstance(der)
        return JcaPEMKeyConverter().getPrivateKey(info)
    }

    private fun parsePublicDer(der: ByteArray, algorithm: String): PublicKey {
        val algo = when {
            algorithm.contains("EC", true) -> "EC"
            algorithm.contains("RSA", true) -> "RSA"
            else -> algorithm
        }
        return KeyFactory.getInstance(algo).generatePublic(X509EncodedKeySpec(der))
    }

    private fun parseCertChainPem(pem: String): List<Certificate> {
        val out = ArrayList<Certificate>()
        val blocks = pem.split("-----BEGIN CERTIFICATE-----")
        for (b in blocks) {
            if (!b.contains("-----END CERTIFICATE-----")) continue
            val body = b.substringBefore("-----END CERTIFICATE-----")
            val der = Base64.decode(body.replace("\\s".toRegex(), ""), Base64.DEFAULT)
            out.add(cf.generateCertificate(java.io.ByteArrayInputStream(der)) as X509Certificate)
        }
        return out
    }
}
