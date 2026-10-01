cmake_minimum_required(VERSION 3.20)
if (POLICY CMP0184)
    cmake_policy(SET CMP0184 NEW)
endif()
set(CMAKE_MSVC_RUNTIME_CHECKS "")
project(everbloom_driver LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Apply the same setting to CMake's ZERO_CHECK project as well as product
# targets; otherwise MSBuild can still initialize FileTracker before reaching
# the actual sources in restricted build environments.
set(CMAKE_VS_GLOBALS "TrackFileAccess=false")

add_library(everbloom_driver_core STATIC
    src/core_protection.cpp
    src/event_bus.cpp
    src/logger.cpp
    src/self_protection.cpp
    src/file_protection.cpp
    src/amsi.cpp
    src/realtime_scan.cpp
    src/network_firewall.cpp
    src/advanced_threat.cpp
    src/irp_dispatcher.cpp
)

target_include_directories(everbloom_driver_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(everbloom_driver_core PRIVATE EVERBLOOM_DRIVER_BUILD)
# Some managed build environments cannot initialize MSBuild's FileTracker
# service. Disable incremental input tracking for this small security core;
# correctness does not depend on stale dependency logs.
set_property(TARGET everbloom_driver_core PROPERTY VS_GLOBAL_TrackFileAccess false)

add_executable(everbloom_driver_stub src/main.cpp)
target_link_libraries(everbloom_driver_stub PRIVATE everbloom_driver_core)
set_property(TARGET everbloom_driver_stub PROPERTY VS_GLOBAL_TrackFileAccess false)

# The integer inference core is pure arithmetic with no kernel dependency, so
# it is verified in user mode rather than only inside the .sys image. The same
# header that the driver compiles is compiled here. This target is deliberately
# outside the WDK guard below: it must build and run even on a machine with no
# kernel kit installed, because it is the only automated check on the model
# math. Only the non-paged placement of the weight tables is kernel-specific
# and therefore cannot be covered here.
#
# kernel_model.cpp is linked in as well, not just the header, so the harness
# evaluates the exact model tables and multiplier the driver ships. That file
# includes no kernel header precisely so this is possible.
enable_testing()
add_executable(everbloom_kernel_matrix_tests
    tests_kernel_matrix.cpp
    src/kernel_model.cpp
)
target_include_directories(everbloom_kernel_matrix_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
set_property(TARGET everbloom_kernel_matrix_tests PROPERTY VS_GLOBAL_TrackFileAccess false)
if (MSVC)
    target_compile_options(everbloom_kernel_matrix_tests PRIVATE /W4)
endif()
add_test(NAME everbloom_kernel_matrix COMMAND everbloom_kernel_matrix_tests)

# Altitude-string arithmetic. Header-only and kernel-free, so it is verified
# here rather than only in the load path: the collision-recovery branch it
# serves runs only when a real altitude collision occurs, which cannot be
# reproduced on demand.
add_executable(everbloom_kernel_altitude_tests
    tests_kernel_altitude.cpp
)
target_include_directories(everbloom_kernel_altitude_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
set_property(TARGET everbloom_kernel_altitude_tests PROPERTY VS_GLOBAL_TrackFileAccess false)
if (MSVC)
    target_compile_options(everbloom_kernel_altitude_tests PRIVATE /W4)
endif()
add_test(NAME everbloom_kernel_altitude COMMAND everbloom_kernel_altitude_tests)

option(BUILD_EVERBLOOM_DRIVER_SYS "Build Windows kernel driver .sys target" ON)
if (BUILD_EVERBLOOM_DRIVER_SYS)
    # CMake may preserve a previous `-NOTFOUND` result when a build directory
    # is reconfigured. Clear all WDK probes before resolving the versioned kit.
    unset(WDK_NTDDK_INCLUDE CACHE)
    unset(WDK_SHARED_INCLUDE CACHE)
    unset(WDK_NTOSKRNL_LIB CACHE)
    unset(WDK_WDMSEC_LIB CACHE)
    unset(WDK_FLTMGR_LIB CACHE)
    unset(WDK_FWPKCLNT_LIB CACHE)
    unset(WDK_BUFFEROVERFLOW_LIB CACHE)
    find_path(WDK_NTDDK_INCLUDE ntddk.h
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Include"
            "C:/Program Files/Windows Kits/10/Include"
            "$ENV{WDK_ROOT}"
        PATH_SUFFIXES
            "10.0.28000.0/km"
            "10.0.26100.0/km"
            "10.0/km"
            "10.0/um"
            "km"
            "shared"
            "Include/10.0.28000.0/km"
            "Include/10.0.28000.0/shared"
            "Include/10.0.26100.0/km"
            "Include/10.0.26100.0/shared"
    )
    find_path(WDK_SHARED_INCLUDE ntdef.h
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Include"
            "C:/Program Files/Windows Kits/10/Include"
            "$ENV{WDK_ROOT}"
        PATH_SUFFIXES
            "10.0.28000.0/shared"
            "10.0.28000.0/shared"
            "10.0.26100.0/shared"
            "shared"
    )
    find_library(WDK_NTOSKRNL_LIB ntoskrnl.lib
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Lib"
            "C:/Program Files/Windows Kits/10/Lib"
            "$ENV{WDK_ROOT}"
        PATH_SUFFIXES
            "10.0.28000.0/km/x64"
            "10.0.26100.0/km/x64"
            "10.0/km/x64"
            "10.0/km/x86"
            "km/x64"
            "km/x86"
            "Lib/10.0.28000.0/km/x64"
            "Lib/10.0.28000.0/km/x86"
            "Lib/10.0.26100.0/km/x64"
            "Lib/10.0.26100.0/km/x86"
    )
    # WDMSEC is shipped beside ntoskrnl.lib. Use explicit versioned paths in
    # addition to the generic WDK hint because find_library otherwise treats
    # the nested `Lib/10.x/...` suffix differently across CMake versions.
    # Re-evaluate a stale `-NOTFOUND` value left by an older configure.
    unset(WDK_WDMSEC_LIB CACHE)
    find_library(WDK_WDMSEC_LIB
        NAMES wdmsec wdmsec.lib
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Lib"
            "C:/Program Files/Windows Kits/10/Lib"
            "$ENV{WDK_ROOT}"
        PATHS
            "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.28000.0/km/x64"
            "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/km/x64"
            "C:/Program Files/Windows Kits/10/Lib/10.0.28000.0/km/x64"
            "C:/Program Files/Windows Kits/10/Lib/10.0.26100.0/km/x64"
        PATH_SUFFIXES
            "10.0.28000.0/km/x64"
            "10.0.26100.0/km/x64"
            "10.0/km/x64"
            "km/x64"
    )
    find_library(WDK_FLTMGR_LIB
        NAMES fltMgr fltMgr.lib
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Lib"
            "C:/Program Files/Windows Kits/10/Lib"
        PATH_SUFFIXES
            "10.0.28000.0/km/x64"
            "10.0.26100.0/km/x64"
    )
    find_library(WDK_FWPKCLNT_LIB
        NAMES fwpkclnt fwpkclnt.lib
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Lib"
            "C:/Program Files/Windows Kits/10/Lib"
        PATH_SUFFIXES
            "10.0.28000.0/km/x64"
            "10.0.26100.0/km/x64"
    )
    find_library(WDK_BUFFEROVERFLOW_LIB
        NAMES BufferOverflowK BufferOverflowK.lib
        HINTS
            "C:/Program Files (x86)/Windows Kits/10/Lib"
            "C:/Program Files/Windows Kits/10/Lib"
        PATH_SUFFIXES
            "10.0.28000.0/km/x64"
            "10.0.26100.0/km/x64"
            "km/x64"
    )
    if (WDK_NTDDK_INCLUDE AND WDK_SHARED_INCLUDE AND WDK_NTOSKRNL_LIB
        AND WDK_WDMSEC_LIB AND WDK_FLTMGR_LIB AND WDK_FWPKCLNT_LIB
        AND WDK_BUFFEROVERFLOW_LIB)
        # A kernel image is an NT native executable, not a user-mode DLL.
        # Using an executable target prevents CMake from adding /DLL and lets
        # the linker emit a valid /DRIVER image with the .sys suffix below.
        add_executable(everbloom_driver_sys
            sys_driver.cpp
            src/kernel_policy.cpp
            src/kernel_components.cpp
            src/kernel_model.cpp
        )
        # The .sys target is deliberately standalone. The user-mode policy
        # library uses STL, iostream and mutexes and must never be linked into
        # kernel mode.
        target_include_directories(everbloom_driver_sys PRIVATE
            ${WDK_NTDDK_INCLUDE}
            ${WDK_SHARED_INCLUDE}
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_compile_definitions(everbloom_driver_sys PRIVATE
            NDIS630=1
            _AMD64_=1
            AMD64=1
        )
        target_link_libraries(everbloom_driver_sys PRIVATE
            ${WDK_NTOSKRNL_LIB}
            ${WDK_WDMSEC_LIB}
            ${WDK_FLTMGR_LIB}
            ${WDK_FWPKCLNT_LIB}
            ${WDK_BUFFEROVERFLOW_LIB}
        )
        set_property(TARGET everbloom_driver_sys PROPERTY VS_GLOBAL_TrackFileAccess false)
        set_target_properties(everbloom_driver_sys PROPERTIES
            PREFIX ""
            OUTPUT_NAME "everbloom_driver"
            SUFFIX ".sys"
        )
        if (MSVC)
            target_compile_options(everbloom_driver_sys PRIVATE /GS-)
            # Kernel images cannot link the user-mode _RTC_* helpers that
            # CMake enables for Debug configurations by default.
            set_property(TARGET everbloom_driver_sys PROPERTY MSVC_RUNTIME_CHECKS "")
            # /DRIVER keeps the kernel image subsystem; DriverEntry is the
            # actual entry point and must not be suppressed with /NOENTRY.
            target_link_options(everbloom_driver_sys PRIVATE
                /DRIVER
                /SUBSYSTEM:NATIVE
                /ENTRY:DriverEntry
                /NODEFAULTLIB
                /MANIFEST:NO
                /INTEGRITYCHECK
            )
        endif()

        # Compile the policy path matcher in a user-mode harness as well. The
        # harness excludes the stateful kernel policy table and exercises the
        # exact normalization code used by the driver, including DOS/device
        # namespaces, 8.3 aliases and reparse-normalized paths.
        enable_testing()
        add_executable(everbloom_kernel_policy_path_tests
            tests_kernel_policy_paths.cpp
        )
        target_include_directories(everbloom_kernel_policy_path_tests PRIVATE
            ${WDK_NTDDK_INCLUDE}
            ${WDK_SHARED_INCLUDE}
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_compile_definitions(everbloom_kernel_policy_path_tests PRIVATE
            EVERBLOOM_KERNEL_POLICY_PATH_TEST=1
            NDIS630=1
            _AMD64_=1
            AMD64=1
        )
        if (MSVC)
            target_compile_options(everbloom_kernel_policy_path_tests PRIVATE /Gy)
            target_link_options(everbloom_kernel_policy_path_tests PRIVATE /OPT:REF)
        endif()
        add_test(NAME everbloom_kernel_policy_paths
            COMMAND everbloom_kernel_policy_path_tests)
    else()
        message(WARNING "WDK headers or libraries not found; everbloom_driver_sys will not be built.")
    endif()
endif()
