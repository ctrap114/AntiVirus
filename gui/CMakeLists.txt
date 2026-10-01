cmake_minimum_required(VERSION 3.20)

project(EverbloomSecurityGui LANGUAGES CXX)

set(EVERBLOOM_GUI_RESOURCE_FILES "")
if(WIN32)
    enable_language(RC)
    list(APPEND EVERBLOOM_GUI_RESOURCE_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/everbloom_gui.rc"
    )
endif()

# Keep GUI builds reliable in restricted MSBuild environments. The GUI does
# not depend on incremental FileTracker state for correctness.
set(CMAKE_VS_GLOBALS "TrackFileAccess=false")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(EVERBLOOM_GUI_FORCE_STUB "Build the emergency console stub instead of WinUI" OFF)
set(EVERBLOOM_VCPKG_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet used by the GUI build")

get_filename_component(EVERBLOOM_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(EVERBLOOM_VCPKG_INSTALLED_DIR
    "${EVERBLOOM_REPO_ROOT}/vcpkg/installed/${EVERBLOOM_VCPKG_TRIPLET}"
)
set(EVERBLOOM_NUGET_PACKAGE_DIR "${EVERBLOOM_REPO_ROOT}/external/nuget/packages")

# Windows App SDK is consumed as one tested bundle.  Do not let a random
# package discovered by CMake silently mix with the checked-in WinUI metadata
# and runtime MSIX files: the bootstrap header, C++/WinRT projections and
# runtime packages must all describe the same release.
set(EVERBLOOM_WINAPPSDK_BUNDLE_VERSION "2.3.1" CACHE STRING
    "Windows App SDK bundle version used by the desktop GUI")
set(EVERBLOOM_CPPWINRT_VERSION "2.0.250303.1" CACHE STRING
    "cppwinrt version provided by the pinned vcpkg installation")
set(EVERBLOOM_WINAPPSDK_BUNDLE_ROOT
    "${EVERBLOOM_REPO_ROOT}/external/nuget/Microsoft.WindowsAppSDK.${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION}"
)
set(EVERBLOOM_WINAPPSDK_BUNDLE_NUSPEC
    "${EVERBLOOM_WINAPPSDK_BUNDLE_ROOT}/Microsoft.WindowsAppSDK.nuspec"
)

if(NOT EXISTS "${EVERBLOOM_WINAPPSDK_BUNDLE_NUSPEC}")
    message(FATAL_ERROR
        "The pinned Windows App SDK bundle ${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION} is missing: "
        "${EVERBLOOM_WINAPPSDK_BUNDLE_NUSPEC}")
endif()
file(READ "${EVERBLOOM_WINAPPSDK_BUNDLE_NUSPEC}" EVERBLOOM_WINAPPSDK_NUSPEC_TEXT)
if(NOT EVERBLOOM_WINAPPSDK_NUSPEC_TEXT MATCHES
        "<version>${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION}</version>")
    message(FATAL_ERROR
        "Windows App SDK bundle nuspec version does not match "
        "${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION}.")
endif()

set(EVERBLOOM_WINAPPSDK_FOUNDATION_ROOT
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.Foundation.2.3.5"
)
set(EVERBLOOM_WINAPPSDK_RUNTIME_ROOT
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.Runtime.${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION}"
)
set(EVERBLOOM_WINAPPSDK_BOOTSTRAP_INCLUDE
    "${EVERBLOOM_WINAPPSDK_FOUNDATION_ROOT}/include"
)
set(EVERBLOOM_WINAPPSDK_VERSION_INCLUDE
    "${EVERBLOOM_WINAPPSDK_RUNTIME_ROOT}/include"
)
set(EVERBLOOM_WINAPPSDK_BOOTSTRAP_LIB
    "${EVERBLOOM_WINAPPSDK_FOUNDATION_ROOT}/lib/native/x64/Microsoft.WindowsAppRuntime.Bootstrap.lib"
)
set(EVERBLOOM_WINAPPSDK_BOOTSTRAP_DLL
    "${EVERBLOOM_WINAPPSDK_FOUNDATION_ROOT}/runtimes/win-x64/native/Microsoft.WindowsAppRuntime.Bootstrap.dll"
)

set(EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_DIR
    "${EVERBLOOM_WINAPPSDK_RUNTIME_ROOT}/tools/MSIX/win10-x64"
)
set(EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_FILES
    "Microsoft.WindowsAppRuntime.2.msix"
    "Microsoft.WindowsAppRuntime.Main.2.msix"
    "Microsoft.WindowsAppRuntime.Singleton.2.msix"
    "Microsoft.WindowsAppRuntime.DDLM.2.msix"
)
foreach(runtime_package IN LISTS EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_FILES)
    if(NOT EXISTS "${EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_DIR}/${runtime_package}")
        message(FATAL_ERROR
            "Windows App SDK ${EVERBLOOM_WINAPPSDK_BUNDLE_VERSION} runtime package is missing: "
            "${EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_DIR}/${runtime_package}")
    endif()
endforeach()

if(EXISTS "${EVERBLOOM_VCPKG_INSTALLED_DIR}/share/cppwinrt/cppwinrt-config.cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${EVERBLOOM_VCPKG_INSTALLED_DIR}")
endif()

file(GLOB_RECURSE WINUI_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/winui/*.h"
)

set(EVERBLOOM_GUI_IS_WINUI OFF)
set(EVERBLOOM_WINAPPSDK_TARGET "")
set(EVERBLOOM_HAS_LOCAL_WINAPPSDK OFF)
set(EVERBLOOM_WINRT_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/winrt_generated")

set(EVERBLOOM_WINAPPSDK_WINUI_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.WinUI.2.3.0/metadata/Microsoft.UI.Xaml.winmd"
)
set(EVERBLOOM_WINAPPSDK_TEXT_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.WinUI.2.3.0/metadata/Microsoft.UI.Text.winmd"
)
set(EVERBLOOM_WINAPPSDK_RESOURCES_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.Foundation.2.3.5/metadata/Microsoft.Windows.ApplicationModel.Resources.winmd"
)
set(EVERBLOOM_WINAPPSDK_UI_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.InteractiveExperiences.2.1.3/metadata/10.0.18362.0/Microsoft.UI.winmd"
)
set(EVERBLOOM_WINAPPSDK_GRAPHICS_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.InteractiveExperiences.2.1.3/metadata/10.0.18362.0/Microsoft.Graphics.winmd"
)
set(EVERBLOOM_WINAPPSDK_FOUNDATION_METADATA
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.Foundation.2.3.5/metadata"
)
set(EVERBLOOM_WEBVIEW2_WINMD
    "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.Web.WebView2.1.0.3719.77/lib/Microsoft.Web.WebView2.Core.winmd"
)

if(WIN32 AND NOT EVERBLOOM_GUI_FORCE_STUB)
    find_package(WinAppSdk CONFIG QUIET)
    if(NOT WinAppSdk_FOUND)
        find_package(WinAppSdk COMPONENTS Microsoft.WindowsAppSDK QUIET)
    endif()
    find_package(cppwinrt CONFIG QUIET)

    if(NOT EXISTS "${EVERBLOOM_VCPKG_INSTALLED_DIR}/tools/cppwinrt/cppwinrt.exe")
        message(FATAL_ERROR
            "Pinned cppwinrt ${EVERBLOOM_CPPWINRT_VERSION} tool was not found under "
            "${EVERBLOOM_VCPKG_INSTALLED_DIR}.")
    endif()
    execute_process(
        COMMAND "${EVERBLOOM_VCPKG_INSTALLED_DIR}/tools/cppwinrt/cppwinrt.exe" -help
        RESULT_VARIABLE EVERBLOOM_CPPWINRT_RESULT
        OUTPUT_VARIABLE EVERBLOOM_CPPWINRT_OUTPUT
        ERROR_VARIABLE EVERBLOOM_CPPWINRT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT EVERBLOOM_CPPWINRT_RESULT EQUAL 0)
        message(FATAL_ERROR
            "Unable to query the pinned cppwinrt ${EVERBLOOM_CPPWINRT_VERSION} tool: "
            "${EVERBLOOM_CPPWINRT_ERROR}")
    endif()
    string(REGEX MATCH "C\\+\\+/WinRT v([0-9.]+)" EVERBLOOM_CPPWINRT_VERSION_MATCH
        "${EVERBLOOM_CPPWINRT_OUTPUT}")
    if(NOT EVERBLOOM_CPPWINRT_VERSION_MATCH
            OR NOT "${CMAKE_MATCH_1}" STREQUAL "${EVERBLOOM_CPPWINRT_VERSION}")
        message(FATAL_ERROR
            "cppwinrt tool version mismatch. Expected ${EVERBLOOM_CPPWINRT_VERSION}, "
            "got '${CMAKE_MATCH_1}'.")
    endif()

    foreach(candidate_target IN ITEMS
        WinAppSdk::Microsoft.WindowsAppSDK
        Microsoft.WindowsAppSDK::Microsoft.WindowsAppSDK
        Microsoft::WindowsAppSDK
    )
        if(TARGET ${candidate_target})
            set(EVERBLOOM_WINAPPSDK_TARGET "${candidate_target}")
            break()
        endif()
    endforeach()

    if(TARGET Microsoft::CppWinRT
            AND DEFINED CPPWINRT_TOOL
            AND EXISTS "${EVERBLOOM_WINAPPSDK_WINUI_WINMD}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_TEXT_WINMD}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_RESOURCES_WINMD}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_UI_WINMD}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_GRAPHICS_WINMD}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_FOUNDATION_METADATA}"
            AND EXISTS "${EVERBLOOM_WEBVIEW2_WINMD}")
        set(EVERBLOOM_HAS_LOCAL_WINAPPSDK ON)
    endif()

    if((EVERBLOOM_WINAPPSDK_TARGET OR EVERBLOOM_HAS_LOCAL_WINAPPSDK)
            AND TARGET Microsoft::CppWinRT)
        set(EVERBLOOM_GUI_IS_WINUI ON)
    endif()
endif()

if(EVERBLOOM_GUI_IS_WINUI)
    file(GLOB_RECURSE WINUI_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/winui/*.cpp"
    )
    list(FILTER WINUI_SOURCES EXCLUDE REGEX "placeholder\\.cpp$")
    list(FILTER WINUI_SOURCES EXCLUDE REGEX "vcpkg/.*\\.cpp$")

    # Work-in-progress custom controls.  They are not referenced by any
    # compiled translation unit -- WinUIApp.cpp builds the whole visual tree
    # from local helpers -- and they cannot compile as they stand:
    #   * the C++/WinRT component headers (Everbloom*.h, MaterialAdapter.h)
    #     and the generated *.g.cpp files are neither checked in nor produced
    #     by any step in this project (the cppwinrt invocation below only
    #     emits projections for the Windows App SDK .winmd inputs), and
    #   * App.xaml.cpp is a truncated sketch that targets a different App
    #     class in the winrt::EverbloomSecurity::... namespace, while
    #     main.cpp starts everbloom::gui::App from WinUIApp.h.
    # Keep them in the tree but out of the build until a component-generation
    # step exists.
    set(EVERBLOOM_WIP_CONTROL_SOURCES
        App.xaml
        EverbloomButton
        EverbloomCard
        EverbloomNavigationView
        EverbloomScanRing
        MaterialAdapter
    )
    foreach(wip_source IN LISTS EVERBLOOM_WIP_CONTROL_SOURCES)
        list(FILTER WINUI_SOURCES EXCLUDE REGEX "/${wip_source}\\.cpp$")
    endforeach()

    add_executable(everbloom_gui WIN32
        "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
        ${WINUI_SOURCES}
        ${WINUI_HEADERS}
        ${EVERBLOOM_GUI_RESOURCE_FILES}
    )
    set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/main.cpp" PROPERTIES
        OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/winui/WinUIApp.h"
    )

    target_link_libraries(everbloom_gui PRIVATE
        Microsoft::CppWinRT
        windowsapp
        ole32
        shell32
        advapi32
    )

    if(EVERBLOOM_HAS_LOCAL_WINAPPSDK
            AND EXISTS "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_LIB}"
            AND EXISTS "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_DLL}")
        target_include_directories(everbloom_gui PRIVATE
            "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_INCLUDE}"
            "${EVERBLOOM_WINAPPSDK_VERSION_INCLUDE}"
            "${EVERBLOOM_NUGET_PACKAGE_DIR}/Microsoft.WindowsAppSDK.WinUI.2.3.0/include"
        )
        target_link_libraries(everbloom_gui PRIVATE
            "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_LIB}"
        )
        add_custom_command(TARGET everbloom_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_DLL}"
                "$<TARGET_FILE_DIR:everbloom_gui>/Microsoft.WindowsAppRuntime.Bootstrap.dll"
            COMMENT "Staging Windows App SDK Bootstrap runtime"
            VERBATIM
        )
        install(FILES "${EVERBLOOM_WINAPPSDK_BOOTSTRAP_DLL}"
            DESTINATION bin
        )
    endif()

    if(EVERBLOOM_WINAPPSDK_TARGET)
        target_link_libraries(everbloom_gui PRIVATE ${EVERBLOOM_WINAPPSDK_TARGET})
    endif()

    if(EVERBLOOM_HAS_LOCAL_WINAPPSDK)
        set(EVERBLOOM_WINRT_PROJECTION_STAMP
            "${EVERBLOOM_WINRT_GENERATED_DIR}/everbloom_winrt_projection.stamp"
        )
        add_custom_command(
            OUTPUT "${EVERBLOOM_WINRT_PROJECTION_STAMP}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${EVERBLOOM_WINRT_GENERATED_DIR}"
            COMMAND "${CPPWINRT_TOOL}"
                -input "${EVERBLOOM_WINAPPSDK_UI_WINMD}"
                -input "${EVERBLOOM_WINAPPSDK_GRAPHICS_WINMD}"
                -input "${EVERBLOOM_WINAPPSDK_WINUI_WINMD}"
                -input "${EVERBLOOM_WINAPPSDK_TEXT_WINMD}"
                -input "${EVERBLOOM_WINAPPSDK_RESOURCES_WINMD}"
                -input "${EVERBLOOM_WEBVIEW2_WINMD}"
                -reference "${EVERBLOOM_WINAPPSDK_FOUNDATION_METADATA}"
                -reference sdk
                -output "${EVERBLOOM_WINRT_GENERATED_DIR}"
                -overwrite
            COMMAND ${CMAKE_COMMAND} -E touch "${EVERBLOOM_WINRT_PROJECTION_STAMP}"
            DEPENDS
                "${EVERBLOOM_WINAPPSDK_UI_WINMD}"
                "${EVERBLOOM_WINAPPSDK_GRAPHICS_WINMD}"
                "${EVERBLOOM_WINAPPSDK_WINUI_WINMD}"
                "${EVERBLOOM_WINAPPSDK_TEXT_WINMD}"
                "${EVERBLOOM_WINAPPSDK_RESOURCES_WINMD}"
                "${EVERBLOOM_WEBVIEW2_WINMD}"
            COMMENT "Generating WinUI C++/WinRT projection headers"
            VERBATIM
        )
        add_custom_target(everbloom_winrt_projection
            DEPENDS "${EVERBLOOM_WINRT_PROJECTION_STAMP}"
        )
        add_dependencies(everbloom_gui everbloom_winrt_projection)
        target_include_directories(everbloom_gui PRIVATE "${EVERBLOOM_WINRT_GENERATED_DIR}")
    endif()

    target_compile_definitions(everbloom_gui PRIVATE
        EVERBLOOM_GUI_WINUI=1
    )
    set_property(TARGET everbloom_gui PROPERTY VS_GLOBAL_TrackFileAccess false)

    if(EVERBLOOM_HAS_LOCAL_WINAPPSDK)
        message(STATUS "Building EverbloomSecurity GUI as a WinUI 3 desktop application using local NuGet Windows App SDK packages.")
    else()
        message(STATUS "Building EverbloomSecurity GUI as a WinUI 3 desktop application using a WinAppSdk CMake package.")
    endif()
else()
    add_executable(everbloom_gui
        "${CMAKE_CURRENT_SOURCE_DIR}/winui/placeholder.cpp"
        ${EVERBLOOM_GUI_RESOURCE_FILES}
    )

    if(EVERBLOOM_GUI_FORCE_STUB)
        message(STATUS "Building EverbloomSecurity GUI placeholder because EVERBLOOM_GUI_FORCE_STUB is ON.")
    elseif(WIN32)
        message(WARNING "Windows App SDK metadata or cppwinrt was not found: building console placeholder as everbloom_gui.")
    else()
        message(WARNING "WinUI is Windows-only: building console placeholder as everbloom_gui.")
    endif()
endif()

# Expose the selected backend to CI and packaging diagnostics. A successful
# CMake configure must not silently turn a Windows build into the placeholder.
set(EVERBLOOM_GUI_IS_WINUI "${EVERBLOOM_GUI_IS_WINUI}" CACHE BOOL
    "Whether this configure selected the real WinUI desktop target" FORCE)

target_include_directories(everbloom_gui PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/winui"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources"
)

if(WIN32)
    target_compile_definitions(everbloom_gui PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
endif()

if(MSVC)
    target_compile_options(everbloom_gui PRIVATE
        /permissive-
        /Zc:__cplusplus
        /utf-8
        /EHsc
        /Zi
    )
    target_link_options(everbloom_gui PRIVATE
        /DEBUG
        "/MAP:$<TARGET_FILE_DIR:everbloom_gui>/everbloom_gui.map"
    )
elseif(NOT WIN32)
    target_compile_options(everbloom_gui PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

install(TARGETS everbloom_gui
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES
    "${EVERBLOOM_REPO_ROOT}/tools/register_context_menu.cmd"
    "${EVERBLOOM_REPO_ROOT}/tools/unregister_context_menu.cmd"
    "${EVERBLOOM_REPO_ROOT}/tools/install_windows_app_runtime.cmd"
    DESTINATION bin
)

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/assets/everbloom_icon.png"
    "${CMAKE_CURRENT_SOURCE_DIR}/assets/everbloom_icon.ico"
    DESTINATION share/everbloom/assets
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/assets/sidebar/"
    DESTINATION share/everbloom/assets/sidebar
    FILES_MATCHING
        PATTERN "*.svg"
)

if(EXISTS "${EVERBLOOM_WINAPPSDK_RUNTIME_ROOT}/tools/MSIX/win10-x64")
    install(DIRECTORY "${EVERBLOOM_WINAPPSDK_RUNTIME_MSIX_DIR}/"
        DESTINATION "share/everbloom/windows-app-runtime/win10-x64"
        FILES_MATCHING
            PATTERN "*.msix"
            PATTERN "MSIX.inventory"
    )
endif()

# The active desktop target is WinUI-only. Qt sources are intentionally excluded
# from the repository so there is one supported desktop implementation.
