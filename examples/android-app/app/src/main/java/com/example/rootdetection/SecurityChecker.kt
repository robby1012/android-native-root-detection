package com.example.rootdetection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.util.Log

/**
 * SecurityChecker class that interfaces with the native C++ root detection library.
 * This class provides all the detection methods available in the native library
 * with proper error handling and logging.
 */
class SecurityChecker(private val context: Context) {
    
    companion object {
        private const val TAG = "SecurityChecker"
        
        // Load the native library
        init {
            try {
                System.loadLibrary("mainclib")
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
            }
        }
    }
    
    // =================================================================================
    // NATIVE METHOD DECLARATIONS
    // Note: These method names are obfuscated in the native library for security
    // =================================================================================
    
    /**
     * Detects root binaries and Magisk installation paths
     * Performance: Low impact
     */
    external fun ItGywo(): Boolean
    
    /**
     * Detects Xposed framework installations (classic, EdXposed, LSPosed)
     * Performance: Low impact
     */
    external fun KRfzZL(): Boolean
    
    /**
     * Scans process memory for Magisk patterns
     * Performance: High impact - should be run on background thread
     */
    external fun eEvNpL(): Boolean
    
    /**
     * Scans process memory for Zygisk injection patterns
     * Performance: High impact - should be run on background thread
     */
    external fun MpGNWr(): Boolean
    
    /**
     * Analyzes suspicious system properties
     * Performance: Low impact
     */
    external fun AoppOo(): Boolean
    
    /**
     * Checks bootloader lock status
     * Performance: Low impact
     */
    external fun DEnHnK(): Boolean
    
    /**
     * Multi-layered Frida detection
     * Performance: Medium impact
     */
    external fun PqRtSj(): Boolean
    
    /**
     * Detects Android emulator environments
     * Performance: Low impact
     */
    external fun KaAdOe(): Boolean
    
    /**
     * Detects USB debugging enabled
     * Performance: Low impact
     */
    external fun XkLmNp(): Boolean
    
    /**
     * Detects developer mode enabled
     * Performance: Low impact
     */
    external fun YtWxHm(): Boolean
    
    /**
     * Checks for developer mode via Java (requires implementation in Activity)
     * Performance: Low impact
     */
    external fun bKFQjC(): Boolean
    
    /**
     * Network security analysis (proxy detection, SSL pinning bypass)
     * Performance: Medium impact
     */
    external fun jmKxLnPwR(): Boolean
    
    /**
     * Comprehensive security check combining all detection methods
     * Performance: High impact - should be run on background thread
     */
    external fun kpNvRmQdx(): Boolean
    
    // =================================================================================
    // HIGH-LEVEL DETECTION METHODS
    // =================================================================================
    
    /**
     * Performs basic root detection checks (low performance impact)
     * Safe to run on main thread
     */
    fun performBasicRootDetection(): RootDetectionResult {
        val results = mutableMapOf<String, Boolean>()
        
        try {
            results["rootBinaries"] = ItGywo()
            results["xposedFramework"] = KRfzZL()
            results["systemProperties"] = AoppOo()
            results["bootloaderUnlocked"] = DEnHnK()
            results["emulatorDetected"] = KaAdOe()
            results["usbDebugging"] = XkLmNp()
            results["developerMode"] = YtWxHm() || isDeveloperModeEnabled()
            
            val isRooted = results.values.any { it }
            val detectionMethods = results.filterValues { it }.keys.toList()
            
            return RootDetectionResult(
                isRooted = isRooted,
                detectionMethods = detectionMethods,
                riskLevel = if (isRooted) RiskLevel.HIGH else RiskLevel.LOW,
                performanceImpact = PerformanceImpact.LOW
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error during basic root detection", e)
            return RootDetectionResult(
                isRooted = false,
                detectionMethods = emptyList(),
                riskLevel = RiskLevel.UNKNOWN,
                performanceImpact = PerformanceImpact.LOW,
                error = e.message
            )
        }
    }
    
    /**
     * Performs comprehensive security analysis (high performance impact)
     * Should be run on background thread
     */
    fun performComprehensiveSecurityCheck(): SecurityAnalysisResult {
        val basicResult = performBasicRootDetection()
        val advancedResults = mutableMapOf<String, Boolean>()
        
        try {
            // High-impact checks
            advancedResults["magiskMemoryPatterns"] = eEvNpL()
            advancedResults["zygiskPatterns"] = MpGNWr()
            advancedResults["fridaDetection"] = PqRtSj()
            advancedResults["networkSecurity"] = jmKxLnPwR()
            advancedResults["comprehensiveCheck"] = kpNvRmQdx()
            
            val allThreats = basicResult.detectionMethods + 
                           advancedResults.filterValues { it }.keys.toList()
            
            val riskLevel = when {
                advancedResults.values.any { it } -> RiskLevel.CRITICAL
                basicResult.isRooted -> RiskLevel.HIGH
                else -> RiskLevel.LOW
            }
            
            return SecurityAnalysisResult(
                basicResult = basicResult,
                advancedThreats = advancedResults.filterValues { it }.keys.toList(),
                allDetectedThreats = allThreats,
                overallRiskLevel = riskLevel,
                recommendedActions = generateRecommendations(allThreats, riskLevel)
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error during comprehensive security check", e)
            return SecurityAnalysisResult(
                basicResult = basicResult,
                advancedThreats = emptyList(),
                allDetectedThreats = basicResult.detectionMethods,
                overallRiskLevel = RiskLevel.UNKNOWN,
                recommendedActions = listOf("Unable to complete security analysis"),
                error = e.message
            )
        }
    }
    
    // =================================================================================
    // HELPER METHODS
    // =================================================================================
    
    /**
     * Java-based developer mode detection (fallback method)
     */
    private fun isDeveloperModeEnabled(): Boolean {
        return try {
            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            ) != 0
        } catch (e: Exception) {
            Log.w(TAG, "Unable to check developer mode via Settings", e)
            false
        }
    }
    
    /**
     * Checks if the app is running in debug mode
     */
    fun isDebuggable(): Boolean {
        return try {
            val appInfo = context.packageManager.getApplicationInfo(
                context.packageName, 
                PackageManager.GET_META_DATA
            )
            (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) {
            Log.w(TAG, "Unable to check debug flag", e)
            false
        }
    }
    
    /**
     * Gets device information for analysis
     */
    fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidVersion = Build.VERSION.RELEASE,
            apiLevel = Build.VERSION.SDK_INT,
            buildType = Build.TYPE,
            buildTags = Build.TAGS,
            isEmulator = KaAdOe(),
            isDebuggable = isDebuggable()
        )
    }
    
    /**
     * Generates security recommendations based on detected threats
     */
    private fun generateRecommendations(threats: List<String>, riskLevel: RiskLevel): List<String> {
        val recommendations = mutableListOf<String>()
        
        when (riskLevel) {
            RiskLevel.CRITICAL -> {
                recommendations.add("CRITICAL: Multiple security threats detected")
                recommendations.add("Immediately terminate sensitive operations")
                recommendations.add("Consider blocking app functionality")
            }
            RiskLevel.HIGH -> {
                recommendations.add("High security risk detected")
                recommendations.add("Disable sensitive features")
                recommendations.add("Implement additional verification")
            }
            RiskLevel.MEDIUM -> {
                recommendations.add("Medium security risk detected")
                recommendations.add("Monitor user behavior closely")
                recommendations.add("Consider additional security measures")
            }
            RiskLevel.LOW -> {
                recommendations.add("Security status: Normal")
                recommendations.add("Continue normal operation")
            }
            RiskLevel.UNKNOWN -> {
                recommendations.add("Unable to determine security status")
                recommendations.add("Implement fallback security measures")
            }
        }
        
        // Specific recommendations based on detected threats
        if (threats.contains("rootBinaries")) {
            recommendations.add("Root binaries detected - consider root-specific mitigations")
        }
        if (threats.contains("fridaDetection")) {
            recommendations.add("Dynamic instrumentation detected - implement anti-hooking measures")
        }
        if (threats.contains("emulatorDetected")) {
            recommendations.add("Emulator environment detected - consider additional verification")
        }
        if (threats.contains("networkSecurity")) {
            recommendations.add("Network security threats detected - verify SSL pinning")
        }
        
        return recommendations
    }
}

// =================================================================================
// DATA CLASSES
// =================================================================================

data class RootDetectionResult(
    val isRooted: Boolean,
    val detectionMethods: List<String>,
    val riskLevel: RiskLevel,
    val performanceImpact: PerformanceImpact,
    val error: String? = null
)

data class SecurityAnalysisResult(
    val basicResult: RootDetectionResult,
    val advancedThreats: List<String>,
    val allDetectedThreats: List<String>,
    val overallRiskLevel: RiskLevel,
    val recommendedActions: List<String>,
    val error: String? = null
)

data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val apiLevel: Int,
    val buildType: String,
    val buildTags: String,
    val isEmulator: Boolean,
    val isDebuggable: Boolean
)

enum class RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
}

enum class PerformanceImpact {
    LOW, MEDIUM, HIGH
}
