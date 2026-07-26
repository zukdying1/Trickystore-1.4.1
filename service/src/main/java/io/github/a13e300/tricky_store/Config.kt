package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.os.ServiceManager
import io.github.a13e300.tricky_store.keystore.CertHack
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Runtime configuration for TrickyStore (restored 1.1+ behaviour).
 *
 * target.txt modes:
 *  - package           → AUTO (leaf-hack if TEE works, else generate)
 *  - package!          → force GENERATE
 *  - package?          → force LEAF HACK
 *
 * Optional files:
 *  - security_patch.txt (1.2.1+)
 *  - tee_status         (auto mode TEE probe cache)
 *  - keybox.xml / extra *.xml keyboxes
 */
object Config {
    enum class Mode { AUTO, HACK, GENERATE }

    data class CustomPatchLevel(
        val system: String? = null,
        val vendor: String? = null,
        val boot: String? = null,
        val all: String? = null,
    )

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val PATCH_FILE = "security_patch.txt"
    private const val TEE_STATUS_FILE = "tee_status"

    val root = File(CONFIG_PATH)
    val keyDbDir = File(root, "key_db")

    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile var globalPatchLevel: CustomPatchLevel? = null
        private set
    @Volatile private var packagePatchLevels = mapOf<String, CustomPatchLevel>()
    @Volatile private var teeBroken: Boolean? = null

    private val uidPackagesCache = ConcurrentHashMap<Int, Array<String>>()

    private object ConfigObserver :
        FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f = when (event) {
                CLOSE_WRITE, MOVED_TO -> File(root, path)
                DELETE, MOVED_FROM -> null
                else -> return
            }
            when {
                path == TARGET_FILE -> updateTargetPackages(f)
                path == KEYBOX_FILE || path.endsWith(".xml") -> updateKeyBox(f ?: File(root, KEYBOX_FILE))
                path == PATCH_FILE -> updatePatchLevel(f)
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        keyDbDir.mkdirs()
        // Restrict key_db to root (SECURITY.md)
        runCatching {
            Runtime.getRuntime().exec(arrayOf("chmod", "700", keyDbDir.absolutePath)).waitFor()
        }

        val scope = File(root, TARGET_FILE)
        if (scope.exists()) updateTargetPackages(scope)
        else Logger.e("target.txt not found at $scope")

        val keybox = File(root, KEYBOX_FILE)
        if (keybox.exists()) updateKeyBox(keybox)
        else Logger.e("keybox.xml not found at $keybox")

        updatePatchLevel(File(root, PATCH_FILE))
        loadOrProbeTeeStatus()
        ConfigObserver.startWatching()
        Logger.i("Config ready (teeBroken=$teeBroken, modes=${packageModes.size})")
    }

    private fun updateTargetPackages(f: File?) = runCatching {
        val modes = mutableMapOf<String, Mode>()
        f?.readLines()?.forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            when {
                line.endsWith("!") -> modes[line.removeSuffix("!").trim()] = Mode.GENERATE
                line.endsWith("?") -> modes[line.removeSuffix("?").trim()] = Mode.HACK
                else -> modes[line] = Mode.AUTO
            }
        }
        packageModes = modes
        uidPackagesCache.clear()
        Logger.i("update target packages: $modes")
    }.onFailure { Logger.e("failed to update target files", it) }

    private fun updateKeyBox(f: File?) = runCatching {
        CertHack.readFromXml(if (f != null && f.exists()) f.readText() else null)
    }.onFailure { Logger.e("failed to update keybox", it) }

    private fun updatePatchLevel(f: File?) = runCatching {
        if (f == null || !f.exists()) {
            globalPatchLevel = null
            packagePatchLevels = emptyMap()
            return@runCatching
        }
        val byContext = linkedMapOf<String, MutableList<String>>()
        var ctx = ""
        f.readLines().forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            val m = Regex("^\\[([a-zA-Z0-9_.-]+)]$").find(line)
            if (m != null) {
                ctx = m.groupValues[1]
            } else {
                byContext.getOrPut(ctx) { mutableListOf() }.add(line)
            }
        }
        fun parse(lines: List<String>?): CustomPatchLevel? {
            if (lines.isNullOrEmpty()) return null
            if (lines.size == 1 && '=' !in lines[0]) {
                return CustomPatchLevel(all = lines[0])
            }
            val map = lines.mapNotNull {
                val p = it.split('=', limit = 2)
                if (p.size == 2) p[0].trim().lowercase() to p[1].trim() else null
            }.toMap()
            val all = map["all"]
            return CustomPatchLevel(
                system = map["system"] ?: all,
                vendor = map["vendor"] ?: all,
                boot = map["boot"] ?: all,
                all = all,
            )
        }
        globalPatchLevel = parse(byContext[""])
        val pkgs = mutableMapOf<String, CustomPatchLevel>()
        byContext.forEach { (k, v) ->
            if (k.isNotEmpty()) parse(v)?.let { pkgs[k] = it }
        }
        packagePatchLevels = pkgs
        Logger.i("security_patch loaded global=$globalPatchLevel packages=${pkgs.keys}")
    }.onFailure { Logger.e("failed to load security_patch.txt", it) }

    /** 1.2.0-RC1: auto mode detects whether hardware crypto / TEE attestation works. */
    fun loadOrProbeTeeStatus() {
        val status = File(root, TEE_STATUS_FILE)
        if (status.exists()) {
            teeBroken = status.readText().trim().contains("true")
            Logger.i("loaded tee_status teeBroken=$teeBroken")
            return
        }
        // Lazy probe is done from daemon after keystore is up; default optimistic.
        teeBroken = false
    }

    fun setTeeBroken(broken: Boolean) {
        teeBroken = broken
        runCatching {
            File(root, TEE_STATUS_FILE).writeText("tee_broken=$broken")
        }
        Logger.i("teeBroken set to $broken")
    }

    fun isTeeBroken(): Boolean = teeBroken == true

    private var iPm: IPackageManager? = null
    private val pmDeath = IBinder.DeathRecipient {
        iPm = null
        Logger.w("PackageManager died")
    }

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            val b = waitService("package") ?: return null
            runCatching { b.linkToDeath(pmDeath, 0) }
            iPm = IPackageManager.Stub.asInterface(b)
        }
        return iPm
    }

    private fun waitService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return runCatching {
                ServiceManager::class.java.getMethod("waitForService", String::class.java)
                    .invoke(null, name) as IBinder
            }.getOrNull() ?: ServiceManager.getService(name)
        }
        repeat(50) {
            ServiceManager.getService(name)?.let { return it }
            Thread.sleep(200)
        }
        return null
    }

    private fun packagesForUid(uid: Int): Array<String> =
        uidPackagesCache.getOrPut(uid) {
            runCatching { getPm()?.getPackagesForUid(uid) }.getOrNull() ?: emptyArray()
        }

    private fun modeForUid(uid: Int): Mode? {
        val pkgs = packagesForUid(uid)
        if (pkgs.isEmpty()) return null
        for (p in pkgs) {
            when (val m = packageModes[p]) {
                Mode.GENERATE -> return Mode.GENERATE
                Mode.HACK -> return Mode.HACK
                Mode.AUTO -> return if (isTeeBroken()) Mode.GENERATE else Mode.HACK
                null -> continue
            }
        }
        return null
    }

    fun needHack(callingUid: Int): Boolean = modeForUid(callingUid) == Mode.HACK
    fun needGenerate(callingUid: Int): Boolean = modeForUid(callingUid) == Mode.GENERATE
    fun shouldProcess(callingUid: Int): Boolean = modeForUid(callingUid) != null

    fun patchLevelForUid(uid: Int): CustomPatchLevel? {
        val pkgs = packagesForUid(uid)
        return pkgs.firstNotNullOfOrNull { packagePatchLevels[it] } ?: globalPatchLevel
    }
}
