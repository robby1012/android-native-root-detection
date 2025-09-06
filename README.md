# Android Native Root Detection Library

A comprehensive C++ library for detecting root access, bypass tools, and security threats on Android devices. This library provides native-level detection mechanisms that are harder to bypass than Java-based solutions.

## 🚀 Features

### Root Detection
- **Binary Detection**: Scans for common root binaries (`su`, `busybox`, etc.)
- **Magisk Detection**: Identifies Magisk installation paths and memory patterns
- **System Property Analysis**: Checks for suspicious build properties and configurations
- **Bootloader Status**: Detects unlocked bootloaders and tampered verified boot states

### Framework Detection
- **Xposed Framework**: Detects Xposed, EdXposed, and LSPosed installations
- **Zygisk Detection**: Identifies Zygisk injection patterns in memory
- **Process Memory Scanning**: Advanced pattern matching in process maps

### Security Analysis
- **Frida Detection**: Multi-layered detection of Frida instrumentation
- **Emulator Detection**: Identifies various Android emulators and virtual environments
- **Debug Detection**: Detects USB debugging, developer mode, and timing anomalies
- **Network Security**: Checks for proxy tools and SSL pinning bypass attempts

### Anti-Bypass Features
- **Timing Analysis**: Detects instrumentation through execution time analysis
- **Memory Pattern Scanning**: Advanced regex-based memory analysis
- **Root Cloaking Detection**: Identifies root hiding applications
- **Comprehensive Security Checks**: Combined threat detection system

## 📋 Requirements

- **Android NDK**: Version 21 or higher
- **CMake**: Version 3.22.1 or higher
- **Android API Level**: 21+ (Android 5.0+)
- **Architecture Support**: ARM64, ARM, x86, x86_64

## 🛠 Installation

### 1. Add to Your Project

Clone or download the library and add it to your Android project:

```bash
git clone https://github.com/your-repo/android-native-root-detection.git
```

### 2. Configure CMake

Add the library to your `CMakeLists.txt`:

```cmake
# Add the native library
add_subdirectory(path/to/android-native-root-detection/src)

# Link against your main library
target_link_libraries(your-app-lib mainclib)
```

### 3. Add JNI Interface

Create JNI method declarations in your Java/Kotlin code (see [examples](./examples/) for complete implementation).

## 📖 Usage

### Basic Root Detection

```java
public class SecurityChecker {
    static {
        System.loadLibrary("mainclib");
    }
    
    // Basic root detection
    public native boolean ItGywo(); // Root binary detection
    public native boolean AoppOo(); // System property analysis
    public native boolean DEnHnK(); // Bootloader status
    
    // Framework detection
    public native boolean KRfzZL(); // Xposed detection
    public native boolean eEvNpL(); // Magisk memory patterns
    public native boolean MpGNWr(); // Zygisk detection
    
    // Advanced security checks
    public native boolean PqRtSj(); // Frida detection
    public native boolean KaAdOe(); // Emulator detection
    public native boolean jmKxLnPwR(); // Network security
    public native boolean kpNvRmQdx(); // Comprehensive check
}
```

### Implementation Example

```java
SecurityChecker checker = new SecurityChecker();

// Perform individual checks
if (checker.ItGywo()) {
    Log.w("Security", "Root binaries detected");
}

if (checker.PqRtSj()) {
    Log.w("Security", "Frida instrumentation detected");
}

// Comprehensive security check
if (checker.kpNvRmQdx()) {
    Log.e("Security", "Security threat detected - app may be compromised");
    // Take appropriate action (exit, disable features, etc.)
}
```

## 🔧 API Reference

### Detection Methods

| Method | Description | Performance Impact |
|--------|-------------|-------------------|
| `ItGywo()` | Detects root binaries and Magisk paths | Low |
| `KRfzZL()` | Detects Xposed framework installations | Low |
| `eEvNpL()` | Scans memory for Magisk patterns | High |
| `MpGNWr()` | Scans memory for Zygisk patterns | High |
| `AoppOo()` | Analyzes system properties | Low |
| `DEnHnK()` | Checks bootloader lock status | Low |
| `PqRtSj()` | Multi-layered Frida detection | Medium |
| `KaAdOe()` | Detects emulator environments | Low |
| `XkLmNp()` | Detects USB debugging | Low |
| `YtWxHm()` | Detects developer mode | Low |
| `jmKxLnPwR()` | Network security analysis | Medium |
| `kpNvRmQdx()` | Comprehensive security check | High |

### Performance Considerations

⚠️ **Important**: Methods marked as "High" performance impact should be run on background threads to avoid blocking the UI.

```java
// Run expensive checks on background thread
new Thread(() -> {
    if (checker.eEvNpL() || checker.MpGNWr()) {
        runOnUiThread(() -> handleSecurityThreat());
    }
}).start();
```

## 🏗 Building

### Debug Build
```bash
cd examples/android-app
./gradlew assembleDebug
```

### Release Build with Obfuscation
```bash
./gradlew assembleRelease
```

For enhanced security, consider using LLVM obfuscation:
```bash
# Add to your CMakeLists.txt
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fobfuscate-all")
```

## 🛡 Security Best Practices

1. **Multi-Layer Detection**: Use multiple detection methods for better coverage
2. **Background Execution**: Run expensive checks on background threads
3. **Fail-Safe Design**: Assume detection methods may be bypassed
4. **Response Strategy**: Have a clear response plan for detected threats
5. **Regular Updates**: Keep detection patterns updated for new bypass techniques

## 📁 Project Structure

```
android-native-root-detection/
├── src/
│   ├── mainClib.cpp          # Main detection library
│   └── CMakeLists.txt        # CMake configuration
├── examples/
│   └── android-app/          # Complete Android application example
│       ├── app/
│       │   ├── src/main/
│       │   │   ├── java/     # Java/Kotlin code
│       │   │   └── cpp/      # Native integration
│       │   └── build.gradle  # App-level Gradle config
│       └── build.gradle      # Project-level Gradle config
├── docs/
│   └── API.md               # Detailed API documentation
├── CHANGELOG.md             # Version history
├── LICENSE                  # License information
└── README.md               # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-detection`)
3. Commit your changes (`git commit -m 'Add amazing detection method'`)
4. Push to the branch (`git push origin feature/amazing-detection`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This library is provided for educational and security research purposes. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction. The detection methods may not catch all possible bypass techniques, and security should be implemented in multiple layers.

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and updates.

## 📞 Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Check the [examples](./examples/) for implementation guidance
- Review the [API documentation](./docs/API.md) for detailed method descriptions
