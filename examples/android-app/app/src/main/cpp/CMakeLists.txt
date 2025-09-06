# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("rootdetection")

set(CMAKE_VERBOSE_MAKEFILE on)
set(can_use_assembler TRUE)
enable_language(ASM)

# Add the main detection library from the parent project
# Adjust the path as needed based on your project structure
set(ROOT_DETECTION_SRC_DIR "../../../../../src")

# Include the original source file
add_library(
    mainclib
    SHARED
    ${ROOT_DETECTION_SRC_DIR}/mainClib.cpp
)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

# Set compiler flags for security and optimization
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -std=c++17")

# For release builds, add additional optimizations and security flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -ffunction-sections -fdata-sections")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG -ffunction-sections -fdata-sections")
    
    # Add link-time optimization if supported
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported)
    if(ipo_supported)
        set_property(TARGET mainclib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Specifies libraries CMake should link to your target library.
target_link_libraries(
    mainclib
    ${log-lib}
    ${android-lib}
    log
)

# Add include directories if needed
target_include_directories(mainclib PRIVATE ${ROOT_DETECTION_SRC_DIR})

# Strip symbols in release builds for security
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET mainclib POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded $<TARGET_FILE:mainclib>
        COMMENT "Stripping debug symbols from release build"
    )
endif()
