# Android Native Root Detection Example App

A complete Android application demonstrating the usage of the Android Native Root Detection Library.

## 📱 Features

This example app showcases:

- **Comprehensive UI**: User-friendly interface for testing all detection methods
- **Real-time Results**: Live display of security scan results with color-coded status
- **Background Monitoring**: Optional service for continuous security monitoring
- **Device Information**: Detailed device analysis and security posture assessment
- **Performance Optimization**: Proper threading for expensive operations
- **Security Best Practices**: ProGuard configuration, native library protection

## 🏗 Building the Example

### Prerequisites

- Android Studio Arctic Fox (2020.3.1) or later
- Android NDK 21 or higher
- Android SDK API Level 21+ (Android 5.0+)
- CMake 3.22.1+

### Build Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/android-native-root-detection.git
   cd android-native-root-detection/examples/android-app
   ```

2. **Open in Android Studio:**
   - Launch Android Studio
   - Open the `examples/android-app` folder
   - Wait for Gradle sync to complete

3. **Build the project:**
   ```bash
   ./gradlew assembleDebug
   ```

4. **Install on device:**
   ```bash
   ./gradlew installDebug
   ```

### Release Build

For production builds with optimizations and obfuscation:

```bash
./gradlew assembleRelease
```

The release build includes:
- Code obfuscation via ProGuard
- Native library optimization
- Debug symbol stripping
- Resource shrinking

## 📱 App Structure

### Main Components

#### MainActivity
- Primary UI for running security scans
- Implements the `CflWsG()` method required by the native library
- Handles both basic and comprehensive security checks
- Provides device information display

#### SecurityChecker
- Kotlin wrapper for the native C++ library
- High-level API for all detection methods
- Proper error handling and result parsing
- Performance impact categorization

#### SecurityService (Optional)
- Background service for continuous monitoring
- Periodic security checks
- Broadcast notifications for detected threats
- Configurable monitoring intervals

#### SecurityReceiver
- Handles system events (boot, package changes)
- Monitors for installation of suspicious apps
- Responds to security alerts

### Detection Methods Available

The example app provides access to all native detection methods:

| Function | Description | Performance |
|----------|-------------|-------------|
| `ItGywo()` | Root binary detection | Low |
| `KRfzZL()` | Xposed framework detection | Low |
| `eEvNpL()` | Magisk memory pattern scanning | High |
| `MpGNWr()` | Zygisk pattern detection | High |
| `AoppOo()` | System property analysis | Low |
| `DEnHnK()` | Bootloader status check | Low |
| `PqRtSj()` | Frida detection | Medium |
| `KaAdOe()` | Emulator detection | Low |
| `XkLmNp()` | USB debugging detection | Low |
| `YtWxHm()` | Developer mode detection | Low |
| `jmKxLnPwR()` | Network security analysis | Medium |
| `kpNvRmQdx()` | Comprehensive security check | High |

## 🎯 Usage Examples

### Basic Security Check

```kotlin
val securityChecker = SecurityChecker(this)
val result = securityChecker.performBasicRootDetection()

if (result.isRooted) {
    Log.w("Security", "Device is rooted: ${result.detectionMethods}")
    // Handle security threat
}
```

### Comprehensive Analysis (Background Thread)

```kotlin
lifecycleScope.launch(Dispatchers.IO) {
    val result = securityChecker.performComprehensiveSecurityCheck()
    
    withContext(Dispatchers.Main) {
        when (result.overallRiskLevel) {
            RiskLevel.CRITICAL -> handleCriticalThreat(result)
            RiskLevel.HIGH -> handleHighRisk(result)
            else -> continueNormalOperation()
        }
    }
}
```

### Individual Detection Methods

```kotlin
// Quick checks (safe for main thread)
val hasRoot = securityChecker.ItGywo()
val hasXposed = securityChecker.KRfzZL()
val isEmulator = securityChecker.KaAdOe()

// Expensive checks (use background thread)
launch(Dispatchers.IO) {
    val hasMagiskInMemory = securityChecker.eEvNpL()
    val hasFrida = securityChecker.PqRtSj()
}
```

## ⚙️ Configuration

### Gradle Configuration

Key configuration in `app/build.gradle`:

```gradle
android {
    externalNativeBuild {
        cmake {
            path file('src/main/cpp/CMakeLists.txt')
            version '3.22.1'
        }
    }
    
    defaultConfig {
        externalNativeBuild {
            cmake {
                cppFlags '-std=c++17 -fvisibility=hidden'
                abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'
            }
        }
    }
}
```

### Security Configuration

The app includes security best practices:

- **ProGuard**: Obfuscation and code shrinking
- **Native Library Protection**: Symbol stripping and optimization
- **Backup Exclusion**: Sensitive data excluded from backups
- **Debugging Prevention**: Anti-debugging measures in release builds

### Performance Tuning

High-impact detection methods are automatically run on background threads:

```kotlin
// Configure background executor
private val backgroundExecutor = Executors.newFixedThreadPool(2)

// Use coroutines for expensive operations
lifecycleScope.launch(Dispatchers.IO) {
    // Heavy security checks here
}
```

## 🛡 Security Considerations

### Integration Security

1. **Library Loading**: Verify native library integrity
2. **Method Obfuscation**: Use obfuscated JNI method names
3. **Result Validation**: Validate all detection results
4. **Error Handling**: Graceful handling of security check failures

### Response Strategies

Implement appropriate responses based on detected threats:

```kotlin
when (result.overallRiskLevel) {
    RiskLevel.CRITICAL -> {
        // Terminate app or disable critical features
        finishAffinity()
    }
    RiskLevel.HIGH -> {
        // Disable sensitive features
        disableSensitiveOperations()
    }
    RiskLevel.MEDIUM -> {
        // Additional verification
        requireAdditionalAuth()
    }
    RiskLevel.LOW -> {
        // Continue normal operation
        proceedNormally()
    }
}
```

## 📊 Performance Impact

### Memory Usage
- Basic checks: ~1-2MB additional memory
- Comprehensive checks: ~5-10MB during scan
- Background service: ~2-3MB continuous

### CPU Impact
- Basic checks: Negligible (<1% CPU)
- Memory scanning: Moderate (5-15% CPU during scan)
- Network checks: Low (1-5% CPU)

### Battery Impact
- Foreground scans: Minimal impact
- Background monitoring: <1% battery per day (15-minute intervals)

## 🔧 Customization

### Modify Detection Parameters

Edit the native library source to adjust detection thresholds:

```cpp
// In mainClib.cpp
const long long expected_duration = 1000; // Timing threshold
const float variance_threshold = 5.0f;     // Variance allowance
```

### Add Custom Detection Methods

1. Add new native function in `mainClib.cpp`
2. Declare JNI method in `SecurityChecker.kt`
3. Update UI to display new detection results

### Configure Background Monitoring

Adjust monitoring frequency in `SecurityService.kt`:

```kotlin
private const val MONITORING_INTERVAL_MINUTES = 15L // Adjust as needed
```

## 🐛 Troubleshooting

### Common Issues

1. **Native Library Not Found**
   - Ensure CMake path is correct
   - Check ABI filters match target devices
   - Verify NDK version compatibility

2. **Detection Methods Returning False**
   - Check device permissions
   - Verify native library loaded correctly
   - Test on different device types

3. **Performance Issues**
   - Run expensive checks on background threads
   - Reduce monitoring frequency
   - Consider selective detection based on use case

### Debug Information

Enable verbose logging for debugging:

```kotlin
// In SecurityChecker.kt
private const val DEBUG = BuildConfig.DEBUG

if (DEBUG) {
    Log.d(TAG, "Detection result: $result")
}
```

## 📞 Support

For questions about the example app:
- Check the main project README
- Review the native library documentation
- Open an issue on GitHub with example app details

## 🔄 Updates

The example app will be updated alongside the main library to demonstrate new features and security improvements.
