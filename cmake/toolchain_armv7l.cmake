# toolchain_armv7l.cmake - Android NDK cross-compilation toolchain for ARMv7l
#
# This file is used by CMake to cross-compile for ARMv7l (STB target).
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain_armv7l.cmake ..
#
# Requirements:
# - Android NDK 25+ (set ANDROID_NDK environment variable)
#

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 21)  # API level (Android 5.0+)
set(CMAKE_ANDROID_ARCH_ABI armeabi-v7a)
set(CMAKE_ANDROID_ARM_MODE ON)  # ARM mode (not Thumb)

# Android NDK path
if(NOT DEFINED ANDROID_NDK)
    # Try to find NDK
    if(DEFINED ENV{ANDROID_NDK})
        set(ANDROID_NDK $ENV{ANDROID_NDK})
    else()
        # Default locations
        set(NDK_SEARCH_PATHS
            "$ENV{HOME}/Android/Sdk/ndk"
            "$ENV{ANDROID_HOME}/ndk"
        )
        
        foreach(path ${NDK_SEARCH_PATHS})
            if(EXISTS ${path})
                file(GLOB NDK_DIRS "${path}/*")
                if(NDK_DIRS)
                    # Use latest NDK version
                    list(SORT NDK_DIRS)
                    list(REVERSE NDK_DIRS)
                    list(GET NDK_DIRS 0 ANDROID_NDK)
                    break()
                endif()
            endif()
        endforeach()
    endif()
endif()

if(NOT EXISTS "${ANDROID_NDK}")
    message(FATAL_ERROR "Android NDK not found. Set ANDROID_NDK or ENV{ANDROID_NDK}")
endif()

message(STATUS "Using Android NDK: ${ANDROID_NDK}")

# Toolchain paths
set(NDK_TOOLCHAIN "${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64")

if(NOT EXISTS "${NDK_TOOLCHAIN}")
    message(FATAL_ERROR "NDK toolchain not found: ${NDK_TOOLCHAIN}")
endif()

# Compilers
set(CMAKE_C_COMPILER "${NDK_TOOLCHAIN}/bin/armv7a-linux-androideabi21-clang")
set(CMAKE_CXX_COMPILER "${NDK_TOOLCHAIN}/bin/armv7a-linux-androideabi21-clang++")

# Other tools
set(CMAKE_AR "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-ar")
set(CMAKE_RANLIB "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-ranlib")
set(CMAKE_STRIP "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-strip")
set(CMAKE_NM "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-nm")
set(CMAKE_OBJDUMP "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-objdump")
set(CMAKE_READELF "${NDK_TOOLCHAIN}/bin/arm-linux-androideabi-readelf")

# Compiler flags
set(CMAKE_C_FLAGS "-O2 -Wall -Wextra -Werror" CACHE STRING "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DANDROID -D__ANDROID_API__=21")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv7-a -mfloat-abi=softfp -mfpu=neon")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}" CACHE STRING "")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "-static" CACHE STRING "")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--strip-all")

# Search paths
set(CMAKE_FIND_ROOT_PATH "${NDK_TOOLCHAIN}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# BPF compilation (host)
set(CMAKE_BPF_COMPILER "clang")
set(CMAKE_BPF_FLAGS "-target bpf -O2 -g -Wall -Werror")
set(CMAKE_BPF_FLAGS "${CMAKE_BPF_FLAGS} -D__TARGET_ARCH_arm")
set(CMAKE_BPF_FLAGS "${CMAKE_BPF_FLAGS} -I/usr/include/bpf")
set(CMAKE_BPF_FLAGS "${CMAKE_BPF_FLAGS} -fno-stack-protector")

# Libraries
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lbpf -lelf -lz")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -llog")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

message(STATUS "Cross-compilation toolchain configured for ARMv7l")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  CXX Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "  AR: ${CMAKE_AR}")
message(STATUS "  Flags: ${CMAKE_C_FLAGS}")
