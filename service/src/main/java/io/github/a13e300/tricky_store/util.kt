package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.os.Build
import android.os.SystemProperties
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ThreadLocalRandom

fun getTransactCode(clazz: Class<*>, method: String) =
    clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }
        .getInt(null)

// --- Verified boot material (1.4.0 AVB key parse; MediaTek custom algo not supported) ---

private fun hexToBytesOrNull(hex: String?): ByteArray? {
    if (hex == null || hex.length % 2 != 0) return null
    return runCatching { hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }.getOrNull()
}

fun randomBytes(size: Int = 32) = ByteArray(size).also { ThreadLocalRandom.current().nextBytes(it) }

/**
 * Prefer:
 *  1. ro.boot.vbmeta.public_key_digest (standard AVB)
 *  2. previously cached value
 *  3. random (logged)
 *
 * MediaTek custom AVB algorithms are intentionally unsupported (changelog 1.4.0).
 */
val bootKey by lazy {
    hexToBytesOrNull(SystemProperties.get("ro.boot.vbmeta.public_key_digest", null))
        ?: hexToBytesOrNull(SystemProperties.get("ro.boot.vbmeta.digest", null)) // last-resort
        ?: run {
            Logger.w("AVB public key digest unavailable; using random boot key")
            randomBytes()
        }
}

val bootHash by lazy {
    getBootHashFromProp() ?: randomBytes()
}

@OptIn(ExperimentalStdlibApi::class)
fun getBootHashFromProp(): ByteArray? {
    val b = SystemProperties.get("ro.boot.vbmeta.digest", null) ?: return null
    if (b.length != 64) return null
    return b.hexToByteArray()
}

// --- Patch levels (1.2.1 security_patch.txt) ---

const val PATCH_DO_NOT_REPORT = -1

fun parsePatchLevelValue(value: String, long: Boolean): Int? {
    val v = value.trim().lowercase()
    if (v == "no" || v == "none" || v == "null") return PATCH_DO_NOT_REPORT
    if (v == "prop") return null // caller substitutes real prop
    // 20241101 or 2024-11-01 or 202411
    val digits = v.replace("-", "")
    return when {
        digits.length == 8 && digits.all { it.isDigit() } -> {
            if (long) digits.toInt()
            else digits.substring(0, 6).toInt()
        }
        digits.length == 6 && digits.all { it.isDigit() } -> {
            if (long) digits.toInt() * 100 // yyyyMM → yyyyMM00
            else digits.toInt()
        }
        else -> null
    }
}

fun String.convertPatchLevel(long: Boolean) = runCatching {
    val l = split("-")
    if (long) l[0].toInt() * 10000 + l[1].toInt() * 100 + l[2].toInt()
    else l[0].toInt() * 100 + l[1].toInt()
}.onFailure { Logger.e("invalid patch level $this !", it) }
    .getOrDefault(if (long) 20240401 else 202404)

private fun realSystemPatch(long: Boolean): Int =
    Build.VERSION.SECURITY_PATCH.convertPatchLevel(long)

private fun realVendorPatch(long: Boolean): Int {
    val p = SystemProperties.get("ro.vendor.build.security_patch", "")
    if (p.isNotEmpty()) return p.convertPatchLevel(long)
    return realSystemPatch(long)
}

private fun realBootPatch(long: Boolean): Int {
    val p = SystemProperties.get("ro.boot.boot_security_patch", "")
        .ifEmpty { SystemProperties.get("ro.bootimage.build.security_patch", "") }
    if (p.isNotEmpty()) return p.convertPatchLevel(long)
    return realSystemPatch(long)
}

private fun resolveComponent(uid: Int, component: String, long: Boolean): Int {
    val custom = Config.patchLevelForUid(uid)
    val raw = when (component) {
        "system" -> custom?.system ?: custom?.all
        "vendor" -> custom?.vendor ?: custom?.all
        "boot" -> custom?.boot ?: custom?.all
        else -> custom?.all
    }
    if (raw != null) {
        if (raw.equals("prop", true)) {
            return when (component) {
                "vendor" -> realVendorPatch(long)
                "boot" -> realBootPatch(long)
                else -> realSystemPatch(long)
            }
        }
        parsePatchLevelValue(raw, long)?.let { return it }
    }
    return when (component) {
        "vendor" -> realVendorPatch(long)
        "boot" -> realBootPatch(long)
        else -> realSystemPatch(long)
    }
}

fun getOsPatchLevel(uid: Int): Int = resolveComponent(uid, "system", long = false)
fun getVendorPatchLevel(uid: Int): Int = resolveComponent(uid, "vendor", long = true)
fun getBootPatchLevel(uid: Int): Int = resolveComponent(uid, "boot", long = true)

// Legacy lazy defaults (no uid context)
val patchLevel by lazy { realSystemPatch(false) }
val patchLevelLong by lazy { realSystemPatch(true) }

// --- OS version (1.2.0 Android 10-11, 1.3.0 Android 16) ---

private val osVersionMap = mapOf(
    36 to 160000, // Android 16 (Baklava)
    35 to 150000, // Android 15
    34 to 140000, // Android 14
    33 to 130000, // Android 13
    32 to 120100, // Android 12L
    31 to 120000, // Android 12
    30 to 110000, // Android 11
    29 to 100000, // Android 10
)

val osVersion: Int
    get() = osVersionMap[Build.VERSION.SDK_INT] ?: 160000

/** Attestation extension version (KeyMint 4.0 → 400). */
fun getAttestVersion(securityLevel: Int): Int {
    // StrongBox historically caps at 300 in AOSP samples
    if (securityLevel == 2) return 300
    return when {
        Build.VERSION.SDK_INT >= 36 -> 400
        Build.VERSION.SDK_INT >= 34 -> 300
        Build.VERSION.SDK_INT >= 33 -> 200
        Build.VERSION.SDK_INT >= 31 -> 100
        else -> 4
    }
}

fun getKeymasterVersion(securityLevel: Int): Int {
    val a = getAttestVersion(securityLevel)
    return if (a >= 100) a else 41
}

fun IPackageManager.getPackageInfoCompat(name: String, flags: Long, userId: Int) =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getPackageInfo(name, flags, userId)
    } else {
        getPackageInfo(name, flags.toInt(), userId)
    }

fun String.trimLine() = trim().split("\n").joinToString("\n") { it.trim() }

fun normalizeSignatureAlgorithm(algoName: String): String =
    algoName.uppercase().replace("WITH", "with")
