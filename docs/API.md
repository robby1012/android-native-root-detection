# API Documentation

## Overview

The Android Native Root Detection Library provides a comprehensive set of C++ functions accessible via JNI to detect various security threats on Android devices. This document provides detailed information about each detection method, its implementation, and usage recommendations.

## Table of Contents

- [JNI Method Reference](#jni-method-reference)
- [Detection Categories](#detection-categories)
- [Performance Considerations](#performance-considerations)
- [Implementation Details](#implementation-details)
- [Security Best Practices](#security-best-practices)
- [Integration Guide](#integration-guide)

## JNI Method Reference

All JNI methods follow the pattern: `Java_com_your_package_MainActivity_[ObfuscatedName]`

### Root Detection Methods

#### `ItGywo()` - Root Binary Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_ItGywo(JNIEnv *env, jobject thiz)`

**Description:** Detects common root binaries and Magisk installation paths by checking file system locations.

**Detected Items:**
- Root binaries: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, etc.
- Root manager APKs: SuperSU, KingoUser, Magisk Manager
- Magisk paths: `/sbin/magisk`, `/data/adb/magisk`, `/data/adb/modules`
- Custom ROM paths and development builds

**Performance:** Low impact (~0.5ms typical execution time)

**Implementation Notes:**
- Uses timing analysis to detect instrumentation attempts
- Checks over 40 different file paths
- Includes variance threshold detection for bypass tools

**Return Value:** `JNI_TRUE` if root indicators found, `JNI_FALSE` otherwise

#### `AoppOo()` - System Property Analysis
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_AoppOo(JNIEnv *env, jobject thiz)`

**Description:** Analyzes system properties for suspicious combinations indicating root or development builds.

**Checked Properties:**
- `ro.build.tags`: Looks for "test-keys" vs "release-keys"
- `ro.debuggable`: Checks if system is debuggable
- `ro.secure`: Verifies secure boot state
- `ro.boot.verifiedbootstate`: Checks verified boot status
- `ro.boot.flash.locked`: Determines bootloader lock state
- `ro.boot.selinux`: SELinux enforcement status

**Suspicious Combinations:**
- Test keys with green verified boot
- Debuggable system with secure flag
- Unlocked bootloader with release keys
- SELinux in permissive mode

**Performance:** Low impact (~1ms typical execution time)

**Return Value:** `JNI_TRUE` if suspicious properties detected, `JNI_FALSE` otherwise

#### `DEnHnK()` - Bootloader Lock Status
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_DEnHnK(JNIEnv *env, jobject thiz)`

**Description:** Specifically checks the bootloader lock status via system properties.

**Checked Properties:**
- `ro.boot.flash.locked`: Primary bootloader lock indicator

**Values:**
- "0": Unlocked bootloader (returns `JNI_TRUE`)
- "1": Locked bootloader (returns `JNI_FALSE`)
- Other: Treated as suspicious (returns `JNI_TRUE`)

**Performance:** Very low impact (<0.1ms typical execution time)

**Return Value:** `JNI_TRUE` if bootloader is unlocked, `JNI_FALSE` if locked

### Framework Detection Methods

#### `KRfzZL()` - Xposed Framework Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_KRfzZL(JNIEnv *env, jobject thiz)`

**Description:** Detects Xposed Framework installations including EdXposed and LSPosed variants.

**Detected Files:**
- `/system/framework/XposedBridge.jar`
- `/system/lib/libxposed_art.so`
- `/system/lib64/libxposed_art.so`
- Module configuration files

**Detected Properties:**
- `vxp`: VirtualXposed indicator
- `lsposed.version`: LSPosed version
- `xposed.version`: Classic Xposed version

**Performance:** Low impact (~2ms typical execution time)

**Return Value:** `JNI_TRUE` if Xposed framework detected, `JNI_FALSE` otherwise

#### `eEvNpL()` - Magisk Memory Pattern Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_eEvNpL(JNIEnv *env, jobject thiz)`

**Description:** Scans process memory maps across the entire system for Magisk-related patterns.

**Search Pattern:** Regex pattern matching ".*magisk.*" (case-insensitive)

**Scan Scope:**
- All process directories in `/proc/`
- Memory map files (`/proc/[pid]/maps`)
- Pattern matching in loaded libraries and memory segments

**Performance:** High impact (100-500ms typical execution time)
**⚠️ Warning:** Should be run on background thread due to performance impact

**Implementation Notes:**
- Uses optimized regex with pre-compilation
- Handles regex errors gracefully
- Scans all accessible process memory maps

**Return Value:** `JNI_TRUE` if Magisk patterns found in memory, `JNI_FALSE` otherwise

#### `MpGNWr()` - Zygisk Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_MpGNWr(JNIEnv *env, jobject thiz)`

**Description:** Detects Zygisk injection patterns in process memory maps.

**Search Pattern:** Regex pattern matching ".*zygisk.*" (case-insensitive)

**Performance:** High impact (100-500ms typical execution time)
**⚠️ Warning:** Should be run on background thread due to performance impact

**Return Value:** `JNI_TRUE` if Zygisk patterns detected, `JNI_FALSE` otherwise

### Instrumentation Detection Methods

#### `PqRtSj()` - Frida Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_PqRtSj(JNIEnv *env, jobject thiz)`

**Description:** Multi-layered detection of Frida dynamic instrumentation framework.

**Detection Methods:**
1. **Memory Pattern Scanning:** Searches for Frida agent/gadget libraries
2. **Port Detection:** Checks default Frida port (27042) for active connections
3. **File System:** Looks for Frida-related files and pipes
4. **Thread Analysis:** Scans thread names for Frida-specific patterns

**Detected Patterns:**
- Library names: `frida-agent`, `frida-gadget`, `re.frida.server`
- Thread names: "frida", "gumjs", "gmain"
- Network connections to localhost:27042

**Performance:** Medium impact (50-200ms typical execution time)

**Implementation Notes:**
- Uses socket connections with timeouts
- Scans `/proc/self/task/` for thread analysis
- Implements multiple detection vectors for robustness

**Return Value:** `JNI_TRUE` if Frida instrumentation detected, `JNI_FALSE` otherwise

### Environment Detection Methods

#### `KaAdOe()` - Emulator Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_KaAdOe(JNIEnv *env, jobject thiz)`

**Description:** Detects Android emulator environments including AVD, Genymotion, and others.

**Detection Methods:**
1. **System Properties:** Hardware identifiers, QEMU properties
2. **File System:** Emulator-specific files and devices
3. **Hardware Analysis:** CPU architecture vs. ABI consistency
4. **Kernel Information:** Emulator-specific kernel signatures

**Detected Properties:**
- `ro.hardware`: "goldfish", "ranchu", "gce_x86", "android_x86"
- `ro.kernel.qemu`: QEMU presence indicator
- `ro.product.model`: SDK and emulator model names

**Detected Files:**
- `/dev/socket/qemud`, `/dev/qemu_pipe`
- `/system/lib/libc_malloc_debug_qemu.so`
- `/system/bin/qemu-props`

**Performance:** Low impact (~5ms typical execution time)

**Return Value:** `JNI_TRUE` if emulator environment detected, `JNI_FALSE` otherwise

#### `XkLmNp()` - USB Debugging Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_XkLmNp(JNIEnv *env, jobject thiz)`

**Description:** Detects if USB debugging is enabled on the device.

**Detection Methods:**
- `persist.sys.usb.config`: USB configuration containing "adb"
- `init.svc.adbd`: ADB daemon service status
- `/sys/class/android_usb/android0/state`: USB state analysis
- `ro.debuggable`: System debuggable flag

**Performance:** Low impact (~2ms typical execution time)

**Return Value:** `JNI_TRUE` if USB debugging detected, `JNI_FALSE` otherwise

#### `YtWxHm()` - Developer Mode Detection
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_YtWxHm(JNIEnv *env, jobject thiz)`

**Description:** Detects if developer mode is enabled via system properties.

**Checked Properties:**
- `persist.sys.development_settings`: Development settings state
- `debug.debuggerd.enabled`: Debugger enablement
- `persist.sys.show_touches`: Touch visualization setting

**Performance:** Low impact (~1ms typical execution time)

**Return Value:** `JNI_TRUE` if developer mode detected, `JNI_FALSE` otherwise

#### `bKFQjC()` - Java Developer Mode Check
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_bKFQjC(JNIEnv *env, jobject thiz_activity)`

**Description:** Calls back to Java to check developer mode status via Settings API.

**Requirements:**
- Requires implementation of `CflWsG()` method in Java activity
- Java method should check `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`

**Performance:** Low impact (~1ms typical execution time)

**Return Value:** `JNI_TRUE` if developer mode enabled, `JNI_FALSE` otherwise

### Advanced Security Methods

#### `jmKxLnPwR()` - Network Security Analysis
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_jmKxLnPwR(JNIEnv *env, jobject thiz)`

**Description:** Analyzes network security threats including proxy tools and SSL pinning bypass attempts.

**Detection Methods:**
1. **Suspicious Network Endpoints:** Common proxy and debugging tool ports
2. **SSL Pinning Status:** Checks for certificate pinning bypass tools
3. **Instrumentation Detection:** Advanced timing-based detection

**Monitored Ports:**
- 8000, 8080, 8081: Common proxy ports
- 8888, 8889: Fiddler and mitmproxy
- 9000, 9090: Charles proxy and Burp Suite

**Detected Applications:**
- mitmproxy, SSL Kill Switch, HTTP Canary
- Network analysis and certificate bypass tools

**Performance:** Medium impact (100-300ms typical execution time)

**Return Value:** `JNI_TRUE` if network security threats detected, `JNI_FALSE` otherwise

#### `kpNvRmQdx()` - Comprehensive Security Check
**Function Signature:** `JNIEXPORT jboolean JNICALL Java_com_your_package_MainActivity_kpNvRmQdx(JNIEnv *env, jobject thiz)`

**Description:** Executes all security detection methods in sequence for comprehensive threat analysis.

**Included Checks:**
- Root cloaking application detection
- Timing-based debugging detection
- Root management server detection
- Network security analysis
- SSL pinning status verification
- Advanced instrumentation detection

**Performance:** High impact (500-2000ms typical execution time)
**⚠️ Warning:** Should only be run on background thread

**Return Value:** `JNI_TRUE` if any security threats detected, `JNI_FALSE` otherwise

## Detection Categories

### Performance Impact Categories

#### Low Impact (< 10ms)
- Basic file existence checks
- System property analysis
- Simple binary detection
- Bootloader status checks

#### Medium Impact (10ms - 100ms)
- Network connectivity checks
- Framework file detection
- Thread name analysis
- USB debugging detection

#### High Impact (> 100ms)
- Memory map scanning
- Process enumeration
- Comprehensive security analysis
- Network endpoint testing

### Security Risk Levels

#### Low Risk
- Standard device configuration
- No detectable threats
- Normal operation recommended

#### Medium Risk
- Developer options enabled
- USB debugging active
- Additional monitoring recommended

#### High Risk
- Root access detected
- Framework injection present
- Sensitive features should be disabled

#### Critical Risk
- Multiple threats detected
- Active instrumentation identified
- Application termination recommended

## Performance Considerations

### Threading Recommendations

```cpp
// Low impact - Safe for main thread
bool basicCheck = ItGywo() || KRfzZL() || DEnHnK();

// High impact - Use background thread
std::async(std::launch::async, [](){
    return eEvNpL() || MpGNWr() || kpNvRmQdx();
});
```

### Memory Usage

- Basic checks: ~1-2MB additional memory
- Memory scanning: ~10-50MB during operation
- Process enumeration: ~5-20MB temporary allocation

### Optimization Strategies

1. **Selective Detection:** Run only necessary checks based on risk assessment
2. **Caching:** Cache results for repeated calls within time windows
3. **Progressive Scanning:** Start with low-impact checks, escalate as needed
4. **Background Processing:** Use worker threads for expensive operations

## Implementation Details

### Error Handling

All methods include comprehensive error handling:

```cpp
try {
    std::regex pattern(R"(.*pattern.*)", std::regex::optimize);
    return scanFunction(pattern) ? JNI_TRUE : JNI_FALSE;
} catch (const std::regex_error &e) {
    // Log error and return safe default
    return JNI_FALSE;
}
```

### Timing Analysis

Several methods include timing analysis to detect instrumentation:

```cpp
const auto start = std::chrono::high_resolution_clock::now();
// Perform detection logic
const auto end = std::chrono::high_resolution_clock::now();
const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

if (duration.count() > expected_threshold) {
    return JNI_TRUE; // Potential instrumentation detected
}
```

### Regex Optimization

Memory scanning methods use optimized regex patterns:

```cpp
std::regex pattern(R"(.*target.*)", std::regex::optimize | std::regex::icase);
```

## Security Best Practices

### Integration Security

1. **Library Verification:** Verify native library integrity before use
2. **Method Obfuscation:** Use obfuscated JNI method names in production
3. **Result Validation:** Validate all detection results and handle errors gracefully
4. **Defense in Depth:** Use multiple detection methods for comprehensive coverage

### Response Strategies

```kotlin
when (detectedThreats.size) {
    0 -> continueNormalOperation()
    1..2 -> implementAdditionalVerification()
    3..5 -> disableSensitiveFeatures()
    else -> terminateApplication()
}
```

### Anti-Bypass Measures

1. **Timing Variance:** Use variable execution timing to detect hooks
2. **Multiple Vectors:** Implement overlapping detection methods
3. **Dynamic Checking:** Perform checks at multiple application lifecycle points
4. **Result Correlation:** Cross-validate results from different methods

## Integration Guide

### Basic Integration

```kotlin
class SecurityChecker {
    companion object {
        init {
            System.loadLibrary("mainclib")
        }
    }
    
    external fun ItGywo(): Boolean
    external fun KRfzZL(): Boolean
    // ... other methods
}
```

### Error Handling

```kotlin
try {
    val isRooted = securityChecker.ItGywo()
    handleRootDetection(isRooted)
} catch (e: UnsatisfiedLinkError) {
    Log.e("Security", "Native library not loaded", e)
    handleSecurityError()
} catch (e: Exception) {
    Log.e("Security", "Security check failed", e)
    handleSecurityError()
}
```

### Performance Optimization

```kotlin
// Use coroutines for expensive operations
lifecycleScope.launch(Dispatchers.IO) {
    val comprehensiveResult = securityChecker.kpNvRmQdx()
    
    withContext(Dispatchers.Main) {
        handleSecurityResult(comprehensiveResult)
    }
}
```

### Caching Strategy

```kotlin
class SecurityChecker {
    private val resultCache = mutableMapOf<String, Pair<Boolean, Long>>()
    private val cacheTimeout = 60_000L // 1 minute
    
    fun cachedDetection(method: String, detector: () -> Boolean): Boolean {
        val cached = resultCache[method]
        val now = System.currentTimeMillis()
        
        return if (cached != null && (now - cached.second) < cacheTimeout) {
            cached.first
        } else {
            val result = detector()
            resultCache[method] = Pair(result, now)
            result
        }
    }
}
```

## Version Compatibility

### Android API Levels
- **Minimum:** API 21 (Android 5.0)
- **Target:** API 34 (Android 14)
- **Tested:** API 21-34

### Architecture Support
- ARM64 (arm64-v8a): Full support
- ARM (armeabi-v7a): Full support
- x86_64: Full support
- x86: Full support

### NDK Compatibility
- **Minimum:** NDK r21
- **Recommended:** NDK r25+
- **Tested:** NDK r21-r26

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version-specific API changes and additions.
