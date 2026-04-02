package org.matrix.TEESimulator.config

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Manages application configuration, including which packages to process, what operation mode to
 * use, and custom security patch levels. It uses a FileObserver to dynamically reload settings when
 * configuration files change.
 */
object ConfigurationManager {

    /** Defines the processing mode for a given package. */
    enum class Mode {
        /** Automatically decide between GENERATE and PATCH based on TEE status. */
        AUTO,
        /** Patch the attestation of an existing certificate chain. */
        PATCH,
        /** Generate a new certificate chain from scratch. */
        GENERATE,
    }

    // --- Configuration Paths ---
    const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_PACKAGES_FILE = "target.txt"
    private const val TEE_STATUS_FILE = "tee_status.txt"
    private const val PATCH_LEVEL_FILE = "security_patch.txt"
    private val configRoot = File(CONFIG_PATH)

    // --- In-Memory Configuration State ---
    @Volatile private var packageRules = listOf<PackageRule>()
    @Volatile private var isTeeBroken: Boolean? = null
    @Volatile private var globalCustomPatchLevel: CustomPatchLevel? = null
    @Volatile private var packagePatchLevels = mapOf<String, CustomPatchLevel>()

    // Cache for UID to package name resolution.
    private val uidToPackagesCache = ConcurrentHashMap<Int, Array<String>>()

    /**
     * Initializes the configuration manager by loading all settings from disk and starting the file
     * observer to watch for changes.
     */
    fun initialize() {
        configRoot.mkdirs()
        SystemLogger.info("Configuration root is: ${configRoot.absolutePath}")

        // First, ensure the package manager service is running, as the TEE check depends on it.
        // This prevents a race condition on startup.
        SystemLogger.info("Waiting for PackageManagerService to be ready...")
        if (getPackageManager() == null) {
            SystemLogger.error(
                "PackageManagerService is not available. TEE check will likely fail."
            )
        } else {
            SystemLogger.info("PackageManagerService is ready.")
        }

        // Initial load of all configuration files.
        loadTargetPackages(File(configRoot, TARGET_PACKAGES_FILE))
        loadPatchLevelConfig(File(configRoot, PATCH_LEVEL_FILE))
        storeTeeStatus() // Check and store the current TEE status.

        // Start watching for any subsequent file changes.
        ConfigObserver.startWatching()
        SystemLogger.info("Configuration initialized and file observer started.")
    }

    /** Keybox-based certificate patching is disabled in the active profile. */
    fun shouldPatch(uid: Int): Boolean = false

    /** Software certificate generation is disabled in the active profile. */
    fun shouldGenerate(uid: Int): Boolean = false

    /** Determines if no operation is needed for a given UID. */
    fun shouldSkipUid(uid: Int): Boolean = getPackageModeForUid(uid) == null

    /** Resolves the operating mode for a given UID based on its packages and the TEE status. */
    private fun getPackageModeForUid(uid: Int): Mode? {
        // Lazily load TEE status if it hasn't been checked yet.
        if (isTeeBroken == null) loadTeeStatus()

        // Short-circuit for wildcard all-selection. This must run before package resolution,
        // because isolated processes may not resolve to package names.
        if (packageRules.any { it.type == RuleType.ALL }) {
            return resolveMode(Mode.AUTO)
        }

        val packages = getPackagesForUid(uid)
        if (packages.isEmpty()) return null

        // Find the first configured mode for any of the UID's packages.
        for (pkg in packages) {
            when (val mode = findModeForPackage(pkg)) {
                Mode.GENERATE, Mode.PATCH, Mode.AUTO -> return resolveMode(mode)
                null -> continue // No config for this package, check the next one.
            }
        }
        return null // No configuration found for this UID.
    }

    private fun resolveMode(mode: Mode): Mode {
        return when (mode) {
            Mode.AUTO -> if (isTeeBroken == true) Mode.GENERATE else Mode.PATCH
            Mode.GENERATE -> Mode.GENERATE
            Mode.PATCH -> Mode.PATCH
        }
    }

    /**
     * Retrieves the custom patch level configuration for a given UID. It first checks for a
     * package-specific override and falls back to the global configuration.
     *
     * @param uid The UID of the calling application.
     * @return The applicable [CustomPatchLevel], or null if no custom configuration exists.
     */
    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = getPackagesForUid(uid)
        // Find the first package-specific configuration for this UID.
        val packageSpecificPatchLevel =
            packages.firstNotNullOfOrNull { pkg -> packagePatchLevels[pkg] }
        return packageSpecificPatchLevel ?: globalCustomPatchLevel
    }

    /** Loads and parses `target.txt`, which defines package matching rules and processing mode. */
    private fun loadTargetPackages(file: File) {
        if (!file.exists()) {
            SystemLogger.warning("Configuration file not found: ${file.absolutePath}")
            return
        }

        val newRules = mutableListOf<PackageRule>()

        try {
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                if (trimmedLine.startsWith("[") && trimmedLine.endsWith("]")) return@forEach

                when {
                    // Suffix '!' means force GENERATE mode.
                    trimmedLine.endsWith("!") -> {
                        val rule = buildPackageRule(trimmedLine.removeSuffix("!").trim())
                        if (rule != null) {
                            newRules += rule.copy(mode = Mode.GENERATE)
                        }
                    }
                    // Suffix '?' means force PATCH mode.
                    trimmedLine.endsWith("?") -> {
                        val rule = buildPackageRule(trimmedLine.removeSuffix("?").trim())
                        if (rule != null) {
                            newRules += rule.copy(mode = Mode.PATCH)
                        }
                    }
                    // No suffix means AUTO mode.
                    else -> {
                        val rule = buildPackageRule(trimmedLine)
                        if (rule != null) {
                            newRules += rule.copy(mode = Mode.AUTO)
                        }
                    }
                }
            }

            // Atomically update the configuration maps.
            packageRules = newRules
            uidToPackagesCache.clear() // Invalidate cache as package settings have changed.
            val summaryByType = newRules.groupingBy { it.type }.eachCount()
            SystemLogger.info(
                "Successfully loaded ${newRules.size} target rules. typeSummary=$summaryByType"
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    private fun findModeForPackage(packageName: String): Mode? {
        return packageRules.firstOrNull { rule -> rule.matches(packageName) }?.mode
    }

    private fun buildPackageRule(patternText: String): PackageRule? {
        val normalized = patternText.trim()
        if (normalized.isEmpty()) return null

        if (normalized.startsWith("regex:") || (normalized.startsWith("/") && normalized.endsWith("/"))) {
            SystemLogger.warning(
                "Ignore target rule '$normalized': regex syntax is disabled, please use wildcard '*' instead."
            )
            return null
        }

        val type =
            when {
                normalized == "*" -> RuleType.ALL
                normalized.contains('*') -> RuleType.WILDCARD
                else -> RuleType.EXACT
            }

        return PackageRule(raw = normalized, mode = Mode.AUTO, type = type)
    }

    private fun wildcardMatches(pattern: String, text: String): Boolean {
        if (pattern == "*") return true
        if (!pattern.contains('*')) return pattern == text

        val parts = pattern.split('*')
        var index = 0

        if (!pattern.startsWith("*")) {
            val first = parts.firstOrNull() ?: ""
            if (!text.startsWith(first)) return false
            index = first.length
        }

        val start = if (pattern.startsWith("*")) 0 else 1
        val endExclusive = if (pattern.endsWith("*")) parts.size else parts.size - 1
        for (i in start until endExclusive) {
            val part = parts[i]
            if (part.isEmpty()) continue
            val found = text.indexOf(part, index)
            if (found < 0) return false
            index = found + part.length
        }

        if (!pattern.endsWith("*")) {
            val last = parts.lastOrNull() ?: ""
            if (last.isNotEmpty()) {
                return text.endsWith(last) && text.length >= index
            }
        }
        return true
    }

    /**
     * Loads and parses the `security_patch.txt` file, which can define both global and per-package
     * security patch levels.
     */
    private fun loadPatchLevelConfig(file: File) {
        if (!file.exists()) {
            globalCustomPatchLevel = null
            packagePatchLevels = emptyMap()
            return
        }

        try {
            val newPackageLevels = mutableMapOf<String, CustomPatchLevel>()
            var currentContext = "" // Empty string for global context
            val contextLines = mutableMapOf<String, MutableList<String>>()
            val contextRegex = Regex("^\\[([a-zA-Z0-9_.-]+)]$")

            // First pass: group lines by context (global or package-specific).
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                contextRegex.find(trimmedLine)?.let { currentContext = it.groupValues[1] }
                    ?: run {
                        contextLines
                            .computeIfAbsent(currentContext) { mutableListOf() }
                            .add(trimmedLine)
                    }
            }

            // Helper function to parse a set of lines into a CustomPatchLevel object.
            fun parseLines(lines: List<String>?): CustomPatchLevel? {
                if (lines.isNullOrEmpty()) return null

                // Handle simple case: one line sets the patch level for all components.
                if (lines.size == 1 && '=' !in lines[0]) {
                    return CustomPatchLevel(
                        system = null,
                        vendor = null,
                        boot = null,
                        all = lines[0],
                    )
                }

                // Handle key-value pair configuration.
                val map =
                    lines
                        .mapNotNull {
                            val parts = it.split('=', limit = 2)
                            if (parts.size == 2) parts[0].trim().lowercase() to parts[1].trim()
                            else null
                        }
                        .toMap()

                val all = map["all"]
                return CustomPatchLevel(
                    system = map["system"] ?: all,
                    vendor = map["vendor"] ?: all,
                    boot = map["boot"] ?: all,
                    all = all,
                )
            }

            // Parse global and per-package configurations.
            val newGlobalLevel = parseLines(contextLines[""])
            contextLines.remove("") // Remove global context to iterate over packages next

            for ((pkg, lines) in contextLines) {
                parseLines(lines)?.let { newPackageLevels[pkg] = it }
            }

            // Atomically update the configuration state.
            globalCustomPatchLevel = newGlobalLevel
            packagePatchLevels = newPackageLevels

            SystemLogger.info(
                "Loaded custom security patch levels: global config exists=${newGlobalLevel != null}, " +
                    "${newPackageLevels.size} package-specific configs."
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /** Checks the device's TEE status and writes the result to a file for persistence. */
    private fun storeTeeStatus() {
        val statusFile = File(configRoot, TEE_STATUS_FILE)
        isTeeBroken = !DeviceAttestationService.isTeeFunctional
        try {
            statusFile.writeText("tee_broken=$isTeeBroken")
            SystemLogger.info("TEE status stored: isTeeBroken=$isTeeBroken")
        } catch (e: Exception) {
            SystemLogger.error("Failed to write TEE status to file.", e)
        }
    }

    /** Loads the TEE status from the file. */
    private fun loadTeeStatus() {
        val statusFile = File(configRoot, TEE_STATUS_FILE)
        isTeeBroken =
            if (statusFile.exists()) {
                statusFile.readText().trim() == "tee_broken=true"
            } else {
                null // Status is unknown.
            }
    }

    /**
     * A FileObserver that monitors the configuration directory for changes and triggers reloads of
     * the relevant settings.
     */
    private object ConfigObserver : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO or DELETE) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            SystemLogger.info("Configuration file change detected: $path (event: $event)")

            val file = if (event != DELETE) File(configRoot, path) else null
            when (path) {
                TARGET_PACKAGES_FILE -> loadTargetPackages(file!!)
                PATCH_LEVEL_FILE -> loadPatchLevelConfig(file!!)
                else -> Unit
            }
        }
    }

    // --- System Service Utilities ---

    private var iPackageManager: IPackageManager? = null
    private val pmDeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                (iPackageManager as? IBinder)?.unlinkToDeath(this, 0)
                iPackageManager = null
                SystemLogger.warning("Package manager service died. Will try to reconnect.")
            }
        }

    /** Retrieves an instance of the IPackageManager service. */
    fun getPackageManager(): IPackageManager? {
        if (iPackageManager == null) {
            // Use a robust method to get the service binder.
            val binder = waitForSystemService("package") ?: return null
            binder.linkToDeath(pmDeathRecipient, 0)
            iPackageManager = IPackageManager.Stub.asInterface(binder)
        }
        return iPackageManager
    }

    /** Retrieves the package names associated with a UID. */
    fun getPackagesForUid(uid: Int): Array<String> {
        return uidToPackagesCache.getOrPut(uid) {
            try {
                getPackageManager()?.getPackagesForUid(uid) ?: emptyArray()
            } catch (e: Exception) {
                SystemLogger.warning("Failed to get packages for UID $uid", e)
                emptyArray()
            }
        }
    }

    /** Waits for a system service to become available, with retries. */
    private fun waitForSystemService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return ServiceManager.waitForService(name)
        }
        // Fallback for older Android versions.
        repeat(70) {
            val service = ServiceManager.getService(name)
            if (service != null) return service
            Thread.sleep(500)
        }
        SystemLogger.error("Failed to get system service after multiple retries: $name")
        return null
    }

    private enum class RuleType {
        EXACT,
        WILDCARD,
        ALL,
    }

    private data class PackageRule(
        val raw: String,
        val mode: Mode,
        val type: RuleType,
    ) {
        fun matches(packageName: String): Boolean {
            return when (type) {
                RuleType.EXACT -> raw == packageName
                RuleType.WILDCARD -> wildcardMatches(raw, packageName)
                RuleType.ALL -> true
            }
        }
    }
}

/** Data class representing custom security patch level overrides. */
data class CustomPatchLevel(
    val system: String?,
    val vendor: String?,
    val boot: String?,
    val all: String?,
)
