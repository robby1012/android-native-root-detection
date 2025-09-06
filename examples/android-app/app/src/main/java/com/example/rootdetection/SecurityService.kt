package com.example.rootdetection

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit

/**
 * Background service for continuous security monitoring.
 * This service can run periodic security checks and notify the app of any threats.
 */
class SecurityService : Service() {

    private lateinit var securityChecker: SecurityChecker
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var monitoringJob: Job? = null

    companion object {
        private const val TAG = "SecurityService"
        private const val MONITORING_INTERVAL_MINUTES = 15L
        
        const val ACTION_SECURITY_THREAT_DETECTED = "com.example.rootdetection.SECURITY_THREAT_DETECTED"
        const val EXTRA_THREAT_LEVEL = "threat_level"
        const val EXTRA_THREAT_METHODS = "threat_methods"
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "SecurityService created")
        
        try {
            securityChecker = SecurityChecker(this)
            startMonitoring()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize SecurityService", e)
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "SecurityService started")
        return START_STICKY // Restart service if killed
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null // This is not a bound service
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "SecurityService destroyed")
        stopMonitoring()
        serviceScope.cancel()
    }

    private fun startMonitoring() {
        monitoringJob = serviceScope.launch {
            while (isActive) {
                try {
                    performSecurityCheck()
                    delay(TimeUnit.MINUTES.toMillis(MONITORING_INTERVAL_MINUTES))
                } catch (e: Exception) {
                    Log.e(TAG, "Error during security monitoring", e)
                    delay(TimeUnit.MINUTES.toMillis(5)) // Shorter delay on error
                }
            }
        }
    }

    private fun stopMonitoring() {
        monitoringJob?.cancel()
        monitoringJob = null
    }

    private suspend fun performSecurityCheck() {
        Log.d(TAG, "Performing background security check")
        
        try {
            // Perform basic security check (low performance impact)
            val basicResult = securityChecker.performBasicRootDetection()
            
            if (basicResult.isRooted) {
                Log.w(TAG, "Security threat detected in background")
                notifySecurityThreat(basicResult.riskLevel, basicResult.detectionMethods)
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Background security check failed", e)
        }
    }

    private fun notifySecurityThreat(riskLevel: RiskLevel, detectionMethods: List<String>) {
        val intent = Intent(ACTION_SECURITY_THREAT_DETECTED).apply {
            putExtra(EXTRA_THREAT_LEVEL, riskLevel.name)
            putStringArrayListExtra(EXTRA_THREAT_METHODS, ArrayList(detectionMethods))
        }
        
        sendBroadcast(intent)
        Log.w(TAG, "Security threat notification sent: $riskLevel")
    }
}
