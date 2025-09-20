//
// Created by Robby Sitanala <robby.sitanala@gmail.com> on 28 Jul 2025.
// best practice : compile with o-llvm (obfuscate LLVM) for better security but added more complexity in the development, your call.
// Notes : All function names obfuscated using random string generator, read the function description
//

#include <jni.h>
#include <string>
#include <vector>
#include <dirent.h>
#include <fstream>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sys/utsname.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
//#include <openssl/sha.h> // Reverting back to standard OpenSSL include
#include <iomanip>
#include <netdb.h>
#include <sys/ptrace.h>
#include <errno.h>

#define LOG_TAG "AslajdakdsAI" // Changed tag slightly for clarity if you have other native logs
// ... (existing LOG_TAG, LOGI, LOGW, get_system_property, file_exists) ...
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__) // Optional for more verbose debugging

// Improved scan_proc_maps to be more versatile for self-scanning
// Scans /proc/[pid]/maps for a pattern.
// If pid is 0 or getpid(), it scans /proc/self/maps.
bool scan_process_maps(pid_t pid_to_scan, const std::regex &pattern) {
    std::string maps_path;
    if (pid_to_scan == 0 || pid_to_scan == getpid()) {
        maps_path = "/proc/self/maps";
    } else {
        maps_path = "/proc/" + std::to_string(pid_to_scan) + "/maps";
    }

    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        //LOGW("Could not open maps file: %s", maps_path.c_str());
        return false;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        if (std::regex_search(line, pattern)) {
            //LOGI("Pattern found in %s: %s", maps_path.c_str(), line.c_str());
            return true;
        }
    }
    return false;
}


// Function to check for default Frida port
// Returns true if connection to localhost:27042 is successful
bool check_frida_default_port() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    bool detected = false;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        //LOGD("Socket creation error for Frida port check");
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(27042); // Default Frida port

    // Convert IPv4 and IPv6 addresses from text to binary form
    // Try connecting to 127.0.0.1
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        //LOGD("Invalid address/ Address not supported for Frida port check");
        close(sock);
        return false;
    }

    // Set a timeout for the connection attempt to avoid long blocking
    struct timeval timeout;
    timeout.tv_sec = 0;  // 0 seconds
    timeout.tv_usec = 100000; // 100 milliseconds
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));


    if (connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0) {
        // Connection successful - Frida server likely running on default port
        //LOGW("Frida detected: Connection to localhost:27042 successful");
        detected = true;
    }

    close(sock);
    return detected;
}


// ... (is_developer_mode_enabled_via_java, other JNI functions) ...

// Utility to get system property using NDK API
std::string get_system_property(const char *prop_name) {
    char value[PROP_VALUE_MAX];
    if (__system_property_get(prop_name, value) > 0) {
        return std::string(value);
    }
    return ""; // Return empty string if property not found or error
}

// Scan /proc/[pid]/maps for a pattern
// Warning, will slow down your app startup significantly if run on UI thread.
// Consider running this on a background thread if critical for startup.
// Returns true if the pattern is found in any process's memory map.
bool scan_proc_maps(const std::regex &pattern) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        //LOGW("Failed to open /proc directory");
        return false;
    }

    struct dirent *entry;
    // Iterate through each entry in the /proc directory
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Skip entries that don't start with a digit (i.e., not a process ID)
        if (!isdigit(entry->d_name[0])) {
            continue;
        }

        // Construct the path to the memory map file of the process
        std::string maps_path = "/proc/";
        maps_path += entry->d_name;
        maps_path += "/maps";

        std::ifstream maps_file(maps_path);
        if (!maps_file.is_open()) {
            //LOGD("Could not open maps file for PID %s: %s", entry->d_name, maps_path.c_str());
            continue; // Skip if the file can't be opened
        }

        std::string line;
        // Read each line of the memory map file
        while (std::getline(maps_file, line)) {
            // Check if the line matches the given regex pattern
            if (std::regex_search(line, pattern)) {
                //LOGI("Pattern found in %s: %s", maps_path.c_str(), line.c_str());
                closedir(proc_dir);
                return true;
            }
        }
        // maps_file is closed automatically when it goes out of scope
    }

    closedir(proc_dir);
    return false; // If no match was found in any process, return false
}

// Utility, check if a file exists
bool file_exists(const char *path) {
    if (access(path, F_OK) == 0) { // access returns 0 on success
        //LOGI("Detected file: %s", path);
        return true;
    }
    return false;
}

// JNI method to detect developer mode by calling a Java method
// Assumes the Java method `CflWsG()` exists in the class passed as 'context' (MainActivity)
// and returns true if developer mode is enabled.
bool is_developer_mode_enabled_via_java(JNIEnv *env, jobject context_object) {
    if (context_object == nullptr) {
        //LOGD("Context object is null in is_developer_mode_enabled_via_java");
        return false; // Cannot proceed without context
    }
    jclass clazz = env->GetObjectClass(context_object);
    if (clazz == nullptr) {
        //LOGD("Failed to get class from context object");
        return false;
    }

    // It's good practice to make the Java method name a constant or pass it if it changes
    const char *java_method_name = "CflWsG";
    jmethodID methodID = env->GetMethodID(clazz, java_method_name, "()Z");
    env->DeleteLocalRef(clazz); // Clean up local reference

    if (methodID == nullptr) {
        //LOGD("Java method '%s' not found in the provided context class!", java_method_name);
        return false;
    }

    jboolean result = env->CallBooleanMethod(context_object, methodID);
    return result == JNI_TRUE;
}


// Function to detect developer mode
// Function to detect developer mode
bool detect_developer_mode() {
    char dev_settings[PROP_VALUE_MAX];
    bool developer_mode_detected = false;

    // Check development settings enabled property
    // THIS IS NOT A RELIABLE OR STANDARD PROPERTY FOR THIS CHECK
    if (__system_property_get("persist.sys.development_settings", dev_settings) > 0) {
        if (strcmp(dev_settings, "1") == 0) {
            //LOGD("Developer mode detected via persist.sys.development_settings"); // Log is okay here
            developer_mode_detected = true;
        }
    }

    // Check global development settings
    // THIS IS NOT A RELIABLE OR STANDARD PROPERTY FOR THIS CHECK
    if (__system_property_get("debug.debuggerd.enabled", dev_settings) > 0) {
        if (strcmp(dev_settings, "1") == 0) {
            // Log message below is incorrect, it references persist.sys.development_settings
            //LOGD("Developer mode detected via persist.sys.development_settings");
            developer_mode_detected = true;
        }
    }

    // Check if show_touches is enabled (common developer option)
    // THIS IS NOT A RELIABLE OR STANDARD PROPERTY FOR THIS CHECK
    if (__system_property_get("persist.sys.show_touches", dev_settings) > 0) {
        if (strcmp(dev_settings, "1") == 0) {
            // Log message below is incorrect, it references persist.sys.development_settings
            //LOGD("Developer mode detected via persist.sys.development_settings");
            developer_mode_detected = true;
        }
    }

    return developer_mode_detected;
}


extern "C" {
//JNI method to ask Java side if developer mode is enabled
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_bKFQjC(JNIEnv *env, jobject thiz_activity) {
    // This 'thiz_activity' should be an instance of MainActivity (or whatever class has CflWsG)
    return is_developer_mode_enabled_via_java(env, thiz_activity) ? JNI_TRUE : JNI_FALSE;
}

// JNI method to detect root binary & common Magisk installation paths
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_ItGywo(JNIEnv *env, jobject /* thiz */) {
    //const auto start = std::chrono::high_resolution_clock::now();
    const std::vector<const char *> paths_to_check = {
            // Existing su binary paths
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/tmp/su",
            "/data/local/su",
            "/data/local/xbin/su",

            // Additional su binary locations
            "/system/sd/xbin/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/bin/failsafe/su",
            "/data/adb/su/bin/su",

            // Root manager APKs
            "/system/app/Superuser.apk",
            "/system/app/Kinguser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/Superuser",
            "/system/app/KingoUser.apk",
            "/data/app/com.topjohnwu.magisk",
            "/data/app/com.kingroot.kinguser",
            "/data/app/com.koushikdutta.superuser",
            "/data/app/eu.chainfire.supersu",

            // Magisk-related paths
            "/sbin/magisk",
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/magisk.db",
            "/data/adb/magisk.img",
            "/data/adb/post-fs-data.d",
            "/cache/magisk.log",
            "/mnt/tirerack/magisk",

            // Additional Magisk paths
            "/data/adb/.magisk",
            "/data/adb/magisk_simple",
            "/data/adb/magisk_debug.log",
            "/data/adb/magisk_merge",
            "/data/adb/.boot_count",
            "/data/adb/modules/*",  // Magisk modules directory

            // Custom ROM superuser locations
            "/system/bin/venomsu",
            "/system/xbin/mu",
            "/system/bin/.ext/.su",
            "/system/etc/init.d/99SuperSUDaemon",

            // Root file system mounts
            "/system/usr/share/superuser",
            "/system/.tor",
            "/.subackup",
            "/su.d"
    };

    for (const char *path: paths_to_check) {
        //LOGD("Checking for root binary: %s", path);
        if (file_exists(path)) {
            //LOGD("Root/Magisk indicator found: %s", path);
            return JNI_TRUE;
        }
    }

    // detecting root files should only took ~500 ms, if longer then bypass tools trying to hook into the system
    /*const auto end = std::chrono::high_resolution_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    //LOGD("Root/Magisk check took %lld microseconds", duration.count());

    const long long expected_duration = 1000; // microseconds
    const float variance_threshold = 1.0f; // 200% variance allowed
    //LOGD("Instrumentation detection duration: %lld us > 1000", duration.count());
    if (duration.count() > (expected_duration * variance_threshold)) {
        return JNI_TRUE;
    }*/

    std::string magisk_version = get_system_property("ro.magisk.version");
    if (!magisk_version.empty()) {
        //LOGD("Magisk detected via system property: ro.magisk.version = %s", magisk_version.c_str());
        return JNI_TRUE;
    }

    // Check for "magisk" in init.rc properties which might indicate early stage loading (requires root to see normally but worth a shot)
    // This is more of an advanced/less reliable check.
    std::string init_magisk = get_system_property("init.svc.magisk");
    if (!init_magisk.empty() && init_magisk == "running") {
        //LOGD("Magisk service detected via init.svc.magisk property");
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

// JNI method to detect Xposed installation files and properties
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_KRfzZL(JNIEnv *env, jobject /* thiz */) {
    const std::vector<const char *> xposed_paths = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/data/data/de.robv.android.xposed.installer/conf/modules.list", // Xposed modules list
            "/data/user_de/0/de.robv.android.xposed.installer/conf/modules.list" // For work profiles
    };

    for (const char *path: xposed_paths) {
        if (file_exists(path)) {
            //LOGD("Xposed indicator found: %s", path);
            return JNI_TRUE;
        }
    }

    // Check for properties related to Xposed or similar frameworks (e.g., EdXposed, LSPosed)
    std::string vxp_prop = get_system_property("vxp"); // VirtualXposed
    if (!vxp_prop.empty() && vxp_prop != "0") {
        //LOGD("Xposed-like framework (VXP) detected via system property 'vxp'");
        return JNI_TRUE;
    }

    std::string lsposed_prop = get_system_property("lsposed.version");
    if (!lsposed_prop.empty()) {
        //LOGD("LSPosed detected via system property 'lsposed.version'");
        return JNI_TRUE;
    }

    // Less common, but sometimes Xposed might set its version as a prop
    std::string xposed_version_prop = get_system_property("xposed.version");
    if (!xposed_version_prop.empty()) {
        //LOGD("Xposed detected via system property 'xposed.version'");
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

// JNI method to detect Magisk patterns in process memory maps
// Warning: Slows down app startup significantly. Consider threading or conditional execution.
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_eEvNpL(JNIEnv *env, jobject /* thiz */) {
    // Using a raw string literal for cleaner regex patterns
    // This pattern is case-insensitive by default in std::regex with ECMAScript grammar.
    // To make it explicitly case-insensitive if needed with other grammars, one might use std::regex::icase.
    try {
        std::regex magisk_pattern(R"(.*magisk.*)", std::regex::optimize); // Pre-compile/optimize
        return scan_proc_maps(magisk_pattern) ? JNI_TRUE : JNI_FALSE;
    } catch (const std::regex_error &e) {
        //LOGD("Regex error for magisk_pattern: %s", e.what());
        return JNI_FALSE; // Or handle error appropriately
    }
}

// JNI method to detect Zygisk injection patterns in process memory maps
// Warning: Slows down app startup significantly. Consider threading or conditional execution.
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_MpGNWr(JNIEnv *env, jobject /* thiz */) {
    try {
        std::regex zygisk_pattern(R"(.*zygisk.*)", std::regex::optimize); // Pre-compile/optimize
        return scan_proc_maps(zygisk_pattern) ? JNI_TRUE : JNI_FALSE;
    } catch (const std::regex_error &e) {
        //LOGD("Regex error for zygisk_pattern: %s", e.what());
        return JNI_FALSE; // Or handle error appropriately
    }
}

// JNI method to detect suspicious combinations of system properties
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_AoppOo(JNIEnv *env, jobject /* thiz */) {
    std::string tags = get_system_property("ro.build.tags");
    //LOGD("Suspicious property: ro.build.tags = '%s'", tags.c_str());
    std::string debuggable = get_system_property("ro.debuggable");
    //LOGD("Suspicious property: ro.debuggable = '%s'", debuggable.c_str());
    std::string secure = get_system_property(
            "ro.secure"); // Typically "1" for secure, "0" for insecure
    std::string verified_boot_state = get_system_property("ro.boot.verifiedbootstate");
    //LOGD("Suspicious property: ro.boot.verifiedbootstate = '%s'", verified_boot_state.c_str());
    std::string flash_locked = get_system_property(
            "ro.boot.flash.locked"); // "1" for locked, "0" for unlocked

    //LOGD("Verifying system properties: %s", secure.c_str());
    // Test keys are a strong indicator of a non-production/modified build
    if (tags.find("test-keys") != std::string::npos) {
        //LOGD("Suspicious property: ro.build.tags contains 'test-keys'");
        return JNI_TRUE;
    }

    // ROM is debuggable
    if (debuggable == "1") {
        //LOGD("Suspicious property: ro.debuggable is '1'");
        return JNI_TRUE;
    }

    // SELinux is not enforcing (permissive). This is a very strong indicator of tampering or a dev build.
    std::string selinux_enforce = get_system_property(
            "ro.boot.selinux"); // could be "permissive" or "enforcing"
    //LOGD("Suspicious property: ro.boot.selinux is '%s'", selinux_enforce.c_str());
    if (selinux_enforce == "permissive") {
        //LOGD("Suspicious property: ro.boot.selinux is 'permissive'");
        return JNI_TRUE;
    }
    // Fallback or alternative check for SELinux status
    std::string enforce_status = get_system_property(
            "getenforce"); // Can be read via shell, might not work directly this way
    // For direct check, one might need to read /sys/fs/selinux/enforce
    // However, checking ro.boot.selinux is more reliable from props.
    //LOGD("Fallback check for SELinux status: %s", enforce_status.c_str());
    // If bootloader is unlocked, it's a significant security risk indicator
    if (flash_locked == "0") {
        //LOGD("Suspicious property: ro.boot.flash.locked is '0' (unlocked bootloader)");
        return JNI_TRUE;
    }

    // Verified boot state is not 'green' (e.g., 'yellow' or 'orange' or 'red')
    if (verified_boot_state != "green" && !verified_boot_state.empty()) {
        //LOGD("Suspicious property: ro.boot.verifiedbootstate is '%s'", verified_boot_state.c_str());
        return JNI_TRUE;
    }

    // Your original combined checks (can be kept if they target specific scenarios you've observed)
    // The individual checks above are often stronger on their own.
    // Example: "test-keys" + "green" verified boot might be a custom ROM trying to appear secure.
    if (tags.find("test-keys") != std::string::npos && verified_boot_state == "green") {
        //LOGD("Suspicious combo: test-keys with green verified boot state.");
        return JNI_TRUE; // This is a good specific check.
    }
    // Debuggable + Secure: This combination is less common. A production "secure=1" build usually isn't "debuggable=1".
    if (debuggable == "1" && secure == "1") {
        //LOGD("Suspicious combo: ro.debuggable='1' and ro.secure='1'");
        return JNI_TRUE;
    }
    // Unlocked bootloader + Release keys: Official build but bootloader is unlocked by user.
    // Already covered by flash_locked == "0" check, but keeping if you want this specific log/logic.
    if (flash_locked == "0" && tags.find("release-keys") != std::string::npos) {
        //LOGD("Suspicious combo: Unlocked bootloader with release-keys build.");
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

// JNI method to check bootloader lock state directly
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_DEnHnK(JNIEnv *env, jobject /* this */) {
    std::string flash_locked_status = get_system_property("ro.boot.flash.locked");
    //LOGD("ro.boot.flash.locked = '%s'", flash_locked_status.c_str());
    // "0" means unlocked, "1" means locked.
    // Any other value or empty string can be treated as "not detected as unlocked" or potentially suspicious
    // depending on desired strictness. For detecting "unlocked", checking for "0" is key.
    if (flash_locked_status == "0") {
        //LOGD("Bootloader is unlocked (ro.boot.flash.locked = 0)");
        return JNI_TRUE; // Bootloader is unlocked
    }
    // If you want to be strict and say any state other than "1" (locked) is also a concern:
    if (flash_locked_status != "1") {
        //LOGW("Bootloader is not confirmed locked (ro.boot.flash.locked = '%s')",flash_locked_status.c_str());
        return JNI_TRUE;
    }
    return JNI_FALSE; // Bootloader is locked or state is not "0"
}

// JNI method to detect Frida presence
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_PqRtSj(JNIEnv *env,
                                           jobject /* thiz */) { // Choose a new obfuscated name
    // 1. Scan self memory maps for Frida agent/gadget
    try {
        // Common Frida library names. Add more if known.
        // Regex is case-insensitive by default with ECMAScript. Use std::regex::icase for explicit.
        std::regex frida_pattern(R"(.*frida-(agent|gadget).*\.so|.*/re\.frida\.server.*)",
                                 std::regex::optimize | std::regex::icase);
        if (scan_process_maps(getpid(), frida_pattern)) {
            //LOGD("Frida agent/gadget detected in process memory maps.");
            return JNI_TRUE;
        }
    } catch (const std::regex_error &e) {
        // LOGE("Regex error for frida_pattern: %s", e.what());
        // Continue to other checks
    }

    // 2. Check for default Frida port (27042)
    // This check can be slow or problematic if network permissions are strict or if run on main thread.
    // Consider if this check is appropriate for your app's context.
    // If you run this, ensure it's not on the UI thread in Java if it might block for too long.
    if (check_frida_default_port()) {
        //LOGD("Frida detected: Default port 27042 is open.");
        return JNI_TRUE;
    }

    // 3. (More advanced and less common) Check for Frida-specific named pipes or files in /tmp or /data/local/tmp
    //    Example: Frida server might create named pipes for communication.
    //    This is highly implementation-dependent of the Frida setup.
    const char *frida_pipe_path = "/data/local/tmp/frida-pipe"; // Example
    if (file_exists(frida_pipe_path)) {
        //LOGD("Frida indicator: Found potential Frida pipe at %s", frida_pipe_path);
        return JNI_TRUE;
    }


    // 4. (Advanced and potentially unstable) Check for known Frida thread names
    //    This would involve iterating /proc/self/task/[tid]/comm or using pthread_getname_np if available and matching.
    //    Example thread names: "frida-gumjs-loop", "pool-<number>" created by Frida.
    //    This is more complex and OS-dependent. Example sketch (pseudo-code, needs fleshing out):

    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir) {
        struct dirent *entry;
        while ((entry = readdir(task_dir)) != nullptr) {
            if (isdigit(entry->d_name[0])) { // If it's a thread ID
                std::string comm_path = "/proc/self/task/";
                comm_path += entry->d_name;
                comm_path += "/comm";
                std::ifstream comm_file(comm_path);
                if (comm_file.is_open()) {
                    std::string thread_name;
                    std::getline(comm_file, thread_name);
                    //LOGD("Found thread: %s", thread_name.c_str());
                    if (thread_name.find("frida") != std::string::npos ||
                        thread_name.find("gumjs") != std::string::npos ||
                        thread_name.find("gmain") !=
                        std::string::npos) { // gmain is common in glib loops used by frida
                        //LOGD("Frida-related thread name detected: %s", thread_name.c_str());
                        closedir(task_dir);
                        return JNI_TRUE;
                    }
                }
            }
        }
        closedir(task_dir);
    }


    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_KaAdOe(JNIEnv *env, jobject /* thiz */) {
    // 1. Check common system properties
    std::string hardware = get_system_property("ro.hardware");
    if (hardware == "goldfish" || hardware == "ranchu" || hardware == "gce_x86" ||
        hardware == "android_x86") {
        //LOGD("Emulator detected: ro.hardware = %s", hardware.c_str());
        return JNI_TRUE;
    }

    std::string qemu = get_system_property("ro.kernel.qemu");
    if (qemu == "1") {
        //LOGD("Emulator detected: ro.kernel.qemu = 1");
        return JNI_TRUE;
    }

    std::string product_model = get_system_property("ro.product.model");
    if (product_model.find("sdk") != std::string::npos ||
        product_model.find("emulator") != std::string::npos ||
        product_model.find("Android SDK built for x86") != std::string::npos) { // Common for AVDs
        //LOGD("Emulator detected: ro.product.model = %s", product_model.c_str());
        return JNI_TRUE;
    }

    std::string product_device = get_system_property("ro.product.device");
    if (product_device.find("generic") != std::string::npos ||
        // "generic_x86", "generic_arm64" etc.
        product_device.find("emulator") != std::string::npos) {
        //LOGD("Emulator detected: ro.product.device = %s", product_device.c_str());
        return JNI_TRUE;
    }


    std::string product_manufacturer = get_system_property("ro.product.manufacturer");
    if (product_manufacturer.find("Genymotion") != std::string::npos ||
        product_manufacturer.find("Google") != std::string::npos &&
        product_model.find("SDK") != std::string::npos) { // Google SDK
        //LOGD("Emulator detected: ro.product.manufacturer = %s", product_manufacturer.c_str());
        return JNI_TRUE;
    }

    // 2. Check for known emulator-specific files
    const std::vector<const char *> emulator_files = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so", // Older emulators
            "/sys/qemu_trace",                       // Older emulators
            "/system/bin/qemu-props"                 // QEMU properties service
    };

    for (const char *path: emulator_files) {
        if (file_exists(path)) {
            //LOGD("Emulator detected: file exists %s", path);
            return JNI_TRUE;
        }
    }

    // 3. Check for specific drivers in /proc/devices or modules in /proc/modules
    // This is more involved as it requires parsing these files.
    // Example: Check for "goldfish_pipe" or "qemu_pipe"
    // For brevity, this example doesn't fully implement parsing /proc/devices or /proc/modules,
    // but you could extend file_exists or create a new function to search within these files.
    // For instance, you could read /proc/devices line by line and search for "goldfish" or "qemu".

    // Basic check for kernel name from uname, sometimes contains "qemu" or "goldfish"
    struct utsname uts;
    if (uname(&uts) == 0) {
        std::string release(uts.release);
        std::string version(uts.version);
        if (release.find("qemu") != std::string::npos ||
            release.find("goldfish") != std::string::npos ||
            version.find("qemu") != std::string::npos ||
            version.find("goldfish") != std::string::npos) {
            //LOGD("Emulator detected: uname kernel information contains qemu/goldfish");
            return JNI_TRUE;
        }
    }


    // 4. (Optional) Check CPU info - more complex and less definitive on its own
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    bool is_intel_amd = false;
    while (std::getline(cpuinfo, line)) {
        if (line.find("GenuineIntel") != std::string::npos ||
            line.find("AuthenticAMD") != std::string::npos) {
            is_intel_amd = true;
            break;
        }
    }
    // If you want to be very strict and assume most real devices are ARM:
    if (is_intel_amd) {
        std::string hardware_arch = get_system_property("ro.product.cpu.abi");
        // If CPU is Intel/AMD but ABI is not x86, it's suspicious, but ARM emulators exist.
        //     // This check is tricky.
        if (hardware_arch.find("x86") != std::string::npos) {
            //LOGD("Emulator detected: CPU is Intel/AMD and ABI is x86");
            return JNI_TRUE; // Be cautious with this one, could have false positives or miss ARM emulators.
        }
    }


    // If none of the above checks triggered, assume it's not an emulator (or not one we can easily detect this way)
    return JNI_FALSE;
}

// Function to detect USB debugging
bool detect_usb_debugging() {
    char adb_enabled[PROP_VALUE_MAX];
    char secure_prop[PROP_VALUE_MAX];
    bool debugging_detected = false;

    // Check adb enabled property
    if (__system_property_get("persist.sys.usb.config", adb_enabled) > 0) {
        if (strstr(adb_enabled, "adb") != nullptr) {
            //LOGD("USB Debugging detected: adb enabled in USB config");
            debugging_detected = true;
        }
    }

    // Check settings.global.adb_enabled
    if (__system_property_get("init.svc.adbd", secure_prop) > 0) {
        if (strcmp(secure_prop, "running") == 0) {
            //LOGD("USB Debugging detected: adbd service is running");
            debugging_detected = true;
        }
    }

    // Check if ADB is actively running
    std::ifstream adb_proc("/sys/class/android_usb/android0/state");
    if (adb_proc.is_open()) {
        std::string state;
        std::getline(adb_proc, state);
        if (state == "CONFIGURED") {
            //LOGD("USB Debugging detected: USB in configured state");
            debugging_detected = true;
        }
    }

    // Additional check for developer options
    if (__system_property_get("ro.debuggable", secure_prop) > 0) {
        if (strcmp(secure_prop, "1") == 0) {
            //LOGD("USB Debugging detected: device is debuggable");
            debugging_detected = true;
        }
    }

    return debugging_detected;
}

// JNI method to detect USB debugging
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_XkLmNp(JNIEnv *env, jobject /* thiz */) {
    return detect_usb_debugging() ? JNI_TRUE : JNI_FALSE;
}

// JNI method to detect developer mode
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_YtWxHm(JNIEnv *env, jobject /* thiz */) {
    return detect_developer_mode() ? JNI_TRUE : JNI_FALSE;
}

// Function to calculate SHA256 hash of a file
/*std::string calculate_file_hash(const char* filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to verify system binary integrity
bool verify_system_binary_integrity() {
    // Known good hashes for important system binaries
    // Note: These hashes should be updated for different Android versions
    const std::map<std::string, std::string> known_hashes = {
        {"/system/bin/app_process", "expected_hash_here"},
        {"/system/bin/linker", "expected_hash_here"},
        {"/system/lib/libc.so", "expected_hash_here"}
    };

    for (const auto& entry : known_hashes) {
        std::string calculated_hash = calculate_file_hash(entry.first.c_str());
        if (!calculated_hash.empty() && calculated_hash != entry.second) {
            // LOGW("Binary integrity check failed for %s", entry.first.c_str());
            return false;
        }
    }
    return true;
}*/

// Function to detect root cloaking apps
bool detect_root_cloaking() {
    const std::vector<const char *> cloak_packages = {
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "com.kingouser.com",
            "com.topjohnwu.magiskhide",
            "org.hola.patcher",
            "com.yellowes.su",
            "com.noshufou.android.su.elite",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "com.prefix.rootcloak"
    };

    // Check for package files
    for (const char *package: cloak_packages) {
        std::string path = "/data/data/" + std::string(package);
        if (file_exists(path.c_str())) {
            //LOGD("Root cloaking app detected: %s", package);
            return true;
        }
    }

    return false;
}

// Function to implement timing checks for debug detection
bool detect_debugging_via_timing() {
    auto start = std::chrono::high_resolution_clock::now();

    // Perform some meaningless but time-consuming calculation
    volatile int result = 0;
    for (int i = 0; i < 10000; i++) {
        result += i * i;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // If execution takes significantly longer than expected, debugger might be attached
    // Threshold should be adjusted based on device capabilities
    return duration.count() > 100; // Arbitrary threshold, adjust as needed
}

// Function to check for known root management servers
bool check_root_management_servers() {
    const std::vector<std::pair<const char *, int>> servers = {
            {"127.0.0.1", 5037},  // ADB
            {"127.0.0.1", 27042}, // Frida
            {"127.0.0.1", 23946}, // Substrate
            {"127.0.0.1", 5555}   // Common root manager port
    };

    for (const auto &server: servers) {
        struct sockaddr_in addr;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(server.second);
        addr.sin_addr.s_addr = inet_addr(server.first);

        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms timeout
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
            close(sock);
            //LOGD("Root management server detected at %s:%d", server.first, server.second);
            return true;
        }
        close(sock);
    }
    return false;
}

// Function to check for suspicious network connections
bool check_suspicious_network_connections() {
    const std::vector<std::pair<const char *, int>> suspicious_endpoints = {
            {"127.0.0.1", 8000},
            {"localhost", 8080},  // Common proxy port
            {"127.0.0.1", 8081}, // Common debug proxy
            {"127.0.0.1", 8082}, // Charles proxy default
            {"127.0.0.1", 9000},  // Charles proxy default
            {"127.0.0.1", 9090}, // Common Burp Suite port
            {"127.0.0.1", 8888}, // Fiddler default port
            {"127.0.0.1", 8889}  // mitmproxy default
    };

    for (const auto &endpoint: suspicious_endpoints) {
        struct hostent *host = gethostbyname(endpoint.first);
        if (!host) continue;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(endpoint.second);
        addr.sin_addr = *((struct in_addr *) host->h_addr);

        // Set non-blocking with timeout
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
            close(sock);
            //LOGD("Suspicious network endpoint detected: %s:%d", endpoint.first, endpoint.second);
            return true;
        }
        close(sock);
    }
    return false;
}

// Function to check SSL/certificate pinning status
bool check_ssl_pinning_status() {
    // Check for common certificate pinning bypass tools
    const std::vector<const char *> pinning_bypass_packages = {
            "/data/data/com.mitmproxy.proxy",
            "/data/data/de.duenndns.ssl",
            "/data/data/org.thoughtcrime.sslstrip",
            "/data/data/com.neonorbit.sslunpinning",
            "/data/data/com.guoshi.httpcanary",
            "/data/data/eu.faircode.netguard",
            "/data/data/com.github.megatronking.netbare"
    };

    for (const char *package: pinning_bypass_packages) {
        if (file_exists(package)) {
            //LOGD("SSL pinning bypass tool detected: %s", package);
            return false;
        }
    }

    return true;
}

// Additional timing-based detection for debuggers and dynamic instrumentation
bool detect_instrumentation() {
    const int iterations = 1000000;
    const auto start = std::chrono::high_resolution_clock::now();

    volatile int result = 0;
    for (int i = 0; i < iterations; ++i) {
        result += i;
        if (i % 100 == 0) {
            // Add some branching to detect instruction level instrumentation
            if (result > iterations) {
                result = 0;
            }
        }
    }

    const auto end = std::chrono::high_resolution_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Baseline should be calibrated per device
    // This is a simplified example - in practice, you'd want to do multiple runs
    // and possibly store device-specific baselines
    const long long expected_duration = 1000; // microseconds
    const float variance_threshold = 5.0f; // 500% variance allowed
    //LOGD("Instrumentation detection duration: %lld us > 5000", duration.count());
    return duration.count() > (expected_duration * variance_threshold);
}

// JNI method for network security checks
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_jmKxLnPwR(JNIEnv *env, jobject /* thiz */) {
    if (check_suspicious_network_connections()) {
        return JNI_TRUE;
    }

    if (!check_ssl_pinning_status()) {
        return JNI_TRUE;
    }

    if (detect_instrumentation()) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

// Enhanced security check that combines all detection methods
JNIEXPORT jboolean JNICALL
Java_com_example_rootdetection_SecurityChecker_kpNvRmQdx(JNIEnv *env, jobject /* thiz */) {
    // Run all security checks in sequence
    if (
            detect_root_cloaking()
            || detect_debugging_via_timing()
            || check_root_management_servers()
            || check_suspicious_network_connections()
            || !check_ssl_pinning_status()
            || detect_instrumentation()
            ) {
        LOGD("Security threat detected");
        return JNI_TRUE; // Security threat detected
    }

    return JNI_FALSE; // All security checks passed
}

}