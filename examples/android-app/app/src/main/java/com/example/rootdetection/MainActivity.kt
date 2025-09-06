package com.example.rootdetection

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.rootdetection.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

/**
 * MainActivity demonstrates the usage of the Android Native Root Detection Library.
 * This activity provides a comprehensive UI for testing all detection methods.
 * 
 * Note: This class needs to implement the CflWsG() method required by the native library
 * for developer mode detection via Java.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var securityChecker: SecurityChecker
    private lateinit var resultsAdapter: SecurityResultsAdapter
    private val securityResults = mutableListOf<SecurityResultItem>()
    
    // Background executor for heavy operations
    private val backgroundExecutor = Executors.newFixedThreadPool(2)
    
    companion object {
        private const val TAG = "MainActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        initializeUI()
        initializeSecurity()
        setupRecyclerView()
        
        // Automatically run basic checks on startup
        runBasicSecurityChecks()
    }
    
    /**
     * This method is required by the native library for developer mode detection.
     * The native method bKFQjC() calls this method to check developer mode status.
     */
    fun CflWsG(): Boolean {
        return try {
            Settings.Global.getInt(
                contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            ) != 0
        } catch (e: Exception) {
            Log.w(TAG, "Unable to check developer mode", e)
            false
        }
    }

    private fun initializeUI() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = "Root Detection Demo"
        
        // Set up click listeners
        binding.btnBasicScan.setOnClickListener { runBasicSecurityChecks() }
        binding.btnComprehensiveScan.setOnClickListener { runComprehensiveSecurityCheck() }
        binding.btnDeviceInfo.setOnClickListener { showDeviceInfo() }
        binding.btnClearResults.setOnClickListener { clearResults() }
        
        // Initially disable comprehensive scan button
        updateScanButtonStates(false)
    }
    
    private fun initializeSecurity() {
        try {
            securityChecker = SecurityChecker(this)
            Log.i(TAG, "SecurityChecker initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize SecurityChecker", e)
            showError("Failed to initialize security system: ${e.message}")
        }
    }
    
    private fun setupRecyclerView() {
        resultsAdapter = SecurityResultsAdapter(securityResults)
        binding.recyclerViewResults.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = resultsAdapter
        }
    }
    
    private fun updateScanButtonStates(isScanning: Boolean) {
        binding.btnBasicScan.isEnabled = !isScanning
        binding.btnComprehensiveScan.isEnabled = !isScanning
        
        if (isScanning) {
            binding.progressBar.visibility = android.view.View.VISIBLE
            binding.textStatus.text = "Scanning..."
        } else {
            binding.progressBar.visibility = android.view.View.GONE
            binding.textStatus.text = "Ready"
        }
    }
    
    private fun runBasicSecurityChecks() {
        updateScanButtonStates(true)
        addResult("🔍", "Starting basic security scan...", SecurityStatus.INFO)
        
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = securityChecker.performBasicRootDetection()
                
                withContext(Dispatchers.Main) {
                    handleBasicResults(result)
                    updateScanButtonStates(false)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    handleError("Basic security check failed", e)
                    updateScanButtonStates(false)
                }
            }
        }
    }
    
    private fun runComprehensiveSecurityCheck() {
        // Show warning about performance impact
        AlertDialog.Builder(this)
            .setTitle("Comprehensive Security Check")
            .setMessage("This scan may take several seconds and could impact app performance. Continue?")
            .setPositiveButton("Continue") { _, _ ->
                performComprehensiveScan()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun performComprehensiveScan() {
        updateScanButtonStates(true)
        addResult("🔍", "Starting comprehensive security analysis...", SecurityStatus.INFO)
        
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = securityChecker.performComprehensiveSecurityCheck()
                
                withContext(Dispatchers.Main) {
                    handleComprehensiveResults(result)
                    updateScanButtonStates(false)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    handleError("Comprehensive security check failed", e)
                    updateScanButtonStates(false)
                }
            }
        }
    }
    
    private fun handleBasicResults(result: RootDetectionResult) {
        addResult("📊", "Basic scan completed", SecurityStatus.INFO)
        
        if (result.error != null) {
            addResult("❌", "Scan error: ${result.error}", SecurityStatus.ERROR)
            return
        }
        
        // Overall status
        val statusIcon = if (result.isRooted) "⚠️" else "✅"
        val statusText = if (result.isRooted) "Security threats detected" else "No threats detected"
        val status = if (result.isRooted) SecurityStatus.WARNING else SecurityStatus.SUCCESS
        addResult(statusIcon, statusText, status)
        
        // Individual detection results
        if (result.detectionMethods.isNotEmpty()) {
            addResult("🚨", "Detected threats:", SecurityStatus.WARNING)
            result.detectionMethods.forEach { method ->
                addResult("  •", getDetectionMethodDescription(method), SecurityStatus.WARNING)
            }
        }
        
        // Risk assessment
        val riskColor = when (result.riskLevel) {
            RiskLevel.LOW -> SecurityStatus.SUCCESS
            RiskLevel.MEDIUM -> SecurityStatus.WARNING
            RiskLevel.HIGH, RiskLevel.CRITICAL -> SecurityStatus.ERROR
            RiskLevel.UNKNOWN -> SecurityStatus.INFO
        }
        addResult("📈", "Risk Level: ${result.riskLevel}", riskColor)
        
        // Show security dialog if threats detected
        if (result.isRooted) {
            showSecurityAlert(result.detectionMethods, result.riskLevel)
        }
    }
    
    private fun handleComprehensiveResults(result: SecurityAnalysisResult) {
        addResult("📊", "Comprehensive analysis completed", SecurityStatus.INFO)
        
        if (result.error != null) {
            addResult("❌", "Analysis error: ${result.error}", SecurityStatus.ERROR)
            return
        }
        
        // Advanced threats
        if (result.advancedThreats.isNotEmpty()) {
            addResult("🔥", "Advanced threats detected:", SecurityStatus.ERROR)
            result.advancedThreats.forEach { threat ->
                addResult("  •", getDetectionMethodDescription(threat), SecurityStatus.ERROR)
            }
        }
        
        // Overall risk assessment
        val riskStatus = when (result.overallRiskLevel) {
            RiskLevel.LOW -> SecurityStatus.SUCCESS
            RiskLevel.MEDIUM -> SecurityStatus.WARNING
            RiskLevel.HIGH -> SecurityStatus.ERROR
            RiskLevel.CRITICAL -> SecurityStatus.ERROR
            RiskLevel.UNKNOWN -> SecurityStatus.INFO
        }
        addResult("⚡", "Overall Risk: ${result.overallRiskLevel}", riskStatus)
        
        // Recommendations
        if (result.recommendedActions.isNotEmpty()) {
            addResult("💡", "Recommendations:", SecurityStatus.INFO)
            result.recommendedActions.forEach { action ->
                addResult("  •", action, SecurityStatus.INFO)
            }
        }
        
        // Show critical security dialog if needed
        if (result.overallRiskLevel == RiskLevel.CRITICAL) {
            showCriticalSecurityAlert(result.allDetectedThreats)
        }
    }
    
    private fun showDeviceInfo() {
        val deviceInfo = securityChecker.getDeviceInfo()
        
        val infoText = buildString {
            appendLine("Device Information:")
            appendLine("Manufacturer: ${deviceInfo.manufacturer}")
            appendLine("Model: ${deviceInfo.model}")
            appendLine("Android Version: ${deviceInfo.androidVersion}")
            appendLine("API Level: ${deviceInfo.apiLevel}")
            appendLine("Build Type: ${deviceInfo.buildType}")
            appendLine("Build Tags: ${deviceInfo.buildTags}")
            appendLine("Is Emulator: ${if (deviceInfo.isEmulator) "Yes" else "No"}")
            appendLine("Is Debuggable: ${if (deviceInfo.isDebuggable) "Yes" else "No"}")
        }
        
        AlertDialog.Builder(this)
            .setTitle("Device Information")
            .setMessage(infoText)
            .setPositiveButton("OK", null)
            .show()
            
        // Add to results
        addResult("📱", "Device info retrieved", SecurityStatus.INFO)
    }
    
    private fun clearResults() {
        securityResults.clear()
        resultsAdapter.notifyDataSetChanged()
        binding.textStatus.text = "Ready"
    }
    
    private fun addResult(icon: String, message: String, status: SecurityStatus) {
        val item = SecurityResultItem(
            icon = icon,
            message = message,
            status = status,
            timestamp = System.currentTimeMillis()
        )
        
        securityResults.add(item)
        
        // Update UI on main thread
        if (Looper.myLooper() == Looper.getMainLooper()) {
            resultsAdapter.notifyItemInserted(securityResults.size - 1)
            binding.recyclerViewResults.scrollToPosition(securityResults.size - 1)
        } else {
            Handler(Looper.getMainLooper()).post {
                resultsAdapter.notifyItemInserted(securityResults.size - 1)
                binding.recyclerViewResults.scrollToPosition(securityResults.size - 1)
            }
        }
    }
    
    private fun getDetectionMethodDescription(method: String): String {
        return when (method) {
            "rootBinaries" -> "Root binaries detected (su, busybox, etc.)"
            "xposedFramework" -> "Xposed Framework detected"
            "magiskMemoryPatterns" -> "Magisk patterns found in memory"
            "zygiskPatterns" -> "Zygisk injection detected"
            "systemProperties" -> "Suspicious system properties"
            "bootloaderUnlocked" -> "Bootloader is unlocked"
            "fridaDetection" -> "Frida instrumentation detected"
            "emulatorDetected" -> "Running in emulator environment"
            "usbDebugging" -> "USB debugging enabled"
            "developerMode" -> "Developer mode enabled"
            "networkSecurity" -> "Network security threats detected"
            "comprehensiveCheck" -> "Multiple security threats detected"
            else -> method
        }
    }
    
    private fun showSecurityAlert(threats: List<String>, riskLevel: RiskLevel) {
        val message = buildString {
            appendLine("Security threats have been detected on this device:")
            appendLine()
            threats.forEach { threat ->
                appendLine("• ${getDetectionMethodDescription(threat)}")
            }
            appendLine()
            appendLine("Risk Level: $riskLevel")
            appendLine()
            appendLine("This may indicate that the device has been rooted or is running in an insecure environment.")
        }
        
        AlertDialog.Builder(this)
            .setTitle("⚠️ Security Alert")
            .setMessage(message)
            .setPositiveButton("Acknowledge", null)
            .setCancelable(false)
            .show()
    }
    
    private fun showCriticalSecurityAlert(threats: List<String>) {
        val message = buildString {
            appendLine("CRITICAL SECURITY THREATS DETECTED!")
            appendLine()
            appendLine("Multiple high-risk security issues have been identified:")
            appendLine()
            threats.forEach { threat ->
                appendLine("• ${getDetectionMethodDescription(threat)}")
            }
            appendLine()
            appendLine("The app may be compromised. Consider terminating the session.")
        }
        
        AlertDialog.Builder(this)
            .setTitle("🚨 CRITICAL SECURITY ALERT")
            .setMessage(message)
            .setPositiveButton("Exit App") { _, _ -> finish() }
            .setNegativeButton("Continue at Risk", null)
            .setCancelable(false)
            .show()
    }
    
    private fun handleError(message: String, exception: Exception) {
        Log.e(TAG, message, exception)
        addResult("❌", "$message: ${exception.message}", SecurityStatus.ERROR)
        showError("$message: ${exception.message}")
    }
    
    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
    
    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            R.id.action_settings -> {
                // Open app settings if needed
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun showAboutDialog() {
        val aboutText = """
            Android Native Root Detection Demo
            
            This app demonstrates the capabilities of the Android Native Root Detection Library.
            
            Features:
            • Native C++ detection methods
            • Multiple root detection techniques
            • Framework detection (Xposed, Magisk, etc.)
            • Security threat analysis
            • Performance-optimized scanning
            
            Version: 1.0.0
            Build: Debug
            
            For more information, visit the project repository.
        """.trimIndent()
        
        AlertDialog.Builder(this)
            .setTitle("About")
            .setMessage(aboutText)
            .setPositiveButton("OK", null)
            .show()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        backgroundExecutor.shutdown()
    }
}
