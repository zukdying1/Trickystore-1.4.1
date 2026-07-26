package io.github.a13e300.tricky_store

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * KeyMint 4.0 moduleHash (tag 724) — changelog 1.3.0 / Android 16.
 * Mirrors AOSP keystore2 maintenance.rs: SHA-256 over DER SET of
 * SEQUENCE { packageName OCTET STRING, version INTEGER } sorted by name encoding.
 */
object ModuleHash {
    val value: ByteArray by lazy { compute() }

    private fun compute(): ByteArray = runCatching {
        val modules = apexInfos().map { (name, version) ->
            val nameOctet = DEROctetString(name.toByteArray(Charsets.UTF_8))
            val versionInt = ASN1Integer(version)
            val vec = ASN1EncodableVector().apply {
                add(nameOctet)
                add(versionInt)
            }
            val seq = DERSequence(vec)
            nameOctet.encoded to seq.encoded
        }.sortedWith { a, b -> compareUnsigned(a.first, b.first) }

        val payload = ByteArrayOutputStream()
        modules.forEach { payload.write(it.second) }
        val derSet = encodeDerSet(payload.toByteArray())
        MessageDigest.getInstance("SHA-256").digest(derSet)
    }.getOrElse {
        Logger.e("moduleHash compute failed", it)
        ByteArray(32)
    }

    private fun apexInfos(): List<Pair<String, Long>> {
        val root = File("/apex")
        if (!root.isDirectory) return emptyList()
        val out = mutableListOf<Pair<String, Long>>()
        root.listFiles()?.forEach { dir ->
            if (!dir.isDirectory) return@forEach
            val n = dir.name
            if (n.startsWith(".") || n.contains("@") || n == "sharedlibs") return@forEach
            val manifest = File(dir, "apex_manifest.pb")
            if (!manifest.exists()) return@forEach
            runCatching {
                val bytes = FileInputStream(manifest).use { it.readBytes() }
                MinimalPb.parse(bytes)?.let { out.add(it) }
            }
        }
        return out.distinctBy { it.first }
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun encodeDerSet(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x31) // SET
        writeLen(out, payload.size)
        out.write(payload)
        return out.toByteArray()
    }

    private fun writeLen(out: ByteArrayOutputStream, length: Int) {
        if (length < 0x80) {
            out.write(length)
        } else {
            val bytes = ArrayList<Int>()
            var n = length
            while (n > 0) {
                bytes.add(0, n and 0xff)
                n = n ushr 8
            }
            out.write(0x80 or bytes.size)
            bytes.forEach { out.write(it) }
        }
    }

    /** Minimal protobuf reader for apex_manifest.pb fields 1 (name) and 2 (version). */
    private object MinimalPb {
        fun parse(data: ByteArray): Pair<String, Long>? {
            var pos = 0
            var name: String? = null
            var version: Long? = null
            fun readVarint(): Long {
                var value = 0L
                var shift = 0
                while (pos < data.size) {
                    val b = data[pos++].toInt()
                    value = value or ((b and 0x7f).toLong() shl shift)
                    if (b and 0x80 == 0) return value
                    shift += 7
                }
                return value
            }
            fun skip(wt: Int) {
                when (wt) {
                    0 -> readVarint()
                    1 -> pos += 8
                    2 -> pos += readVarint().toInt()
                    5 -> pos += 4
                    else -> error("wire $wt")
                }
            }
            while (pos < data.size) {
                val tag = readVarint()
                val field = (tag ushr 3).toInt()
                val wt = (tag and 7).toInt()
                when (field) {
                    1 -> {
                        val len = readVarint().toInt()
                        name = String(data, pos, len, Charsets.UTF_8)
                        pos += len
                    }
                    2 -> version = readVarint()
                    else -> skip(wt)
                }
            }
            return if (name != null && version != null) name to version else null
        }
    }
}
