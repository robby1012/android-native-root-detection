package com.example.rootdetection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Broadcast receiver for handling security-related system events.
 * This receiver can monitor for app installations, boot completion, and other events
 * that might affect the security posture of the device.
 */
class SecurityReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SecurityReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(TAG, "Received broadcast: ${intent.action}")
        
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                handleBootCompleted(context)
            }
            Intent.ACTION_PACKAGE_ADDED -> {
                handlePackageAdded(context, intent)
            }
            Intent.ACTION_PACKAGE_REMOVED -> {
                handlePackageRemoved(context, intent)
            }
            SecurityService.ACTION_SECURITY_THREAT_DETECTED -> {
                handleSecurityThreatDetected(context, intent)
            }
        }
    }

    private fun handleBootCompleted(context: Context) {
        Log.i(TAG, "Device boot completed - starting security monitoring")
        
        // Start the security service on boot
        val serviceIntent = Intent(context, SecurityService::class.java)
        context.startService(serviceIntent)
    }

    private fun handlePackageAdded(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart
        Log.d(TAG, "Package added: $packageName")
        
        // Check if the installed package is a known security risk
        packageName?.let { pkg ->
            if (isSecurityRiskPackage(pkg)) {
                Log.w(TAG, "Security risk package installed: $pkg")
                // Could trigger a security check or notification
            }
        }
    }

    private fun handlePackageRemoved(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart
        Log.d(TAG, "Package removed: $packageName")
    }

    private fun handleSecurityThreatDetected(context: Context, intent: Intent) {
        val threatLevel = intent.getStringExtra(SecurityService.EXTRA_THREAT_LEVEL)
        val threatMethods = intent.getStringArrayListExtra(SecurityService.EXTRA_THREAT_METHODS)
        
        Log.w(TAG, "Security threat detected: $threatLevel, methods: $threatMethods")
        
        // Handle the security threat notification
        // Could show a notification, log to analytics, etc.
    }

    private fun isSecurityRiskPackage(packageName: String): Boolean {
        val riskPackages = listOf(
            "com.topjohnwu.magisk",
            "com.devadvance.rootcloak",
            "com.amphoras.hidemyroot",
            "com.formyhm.hiderootPremium",
            "de.robv.android.xposed.installer",
            "com.koushikdutta.superuser",
            "eu.chainfire.supersu",
            "com.kingroot.kinguser",
            "com.kingouser.com"
        )
        
        return riskPackages.any { packageName.contains(it, ignoreCase = true) }
    }
}
