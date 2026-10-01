cmake_minimum_required(VERSION 3.20)

project(EverbloomSecurity VERSION 1.0.0 LANGUAGES CXX C)

include(CTest)
include(GNUInstallDirs)

option(BUILD_DRIVER "Build the optional driver components" OFF)
option(BUILD_TESTS "Build EverbloomSecurity test targets" ON)
option(EVERBLOOM_BUILD_ENGINE
    "Build the Rust engine from source as part of the top-level build"
    ON
)
option(EVERBLOOM_INSTALL_PYTHON
    "Install the Python package in editable mode as part of the native build"
    ON
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(CARGO_EXECUTABLE cargo REQUIRED)
add_subdirectory(gui)

if(EVERBLOOM_BUILD_ENGINE)
    add_custom_target(engine ALL
        COMMAND ${CARGO_EXECUTABLE} build --release --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/engine/Cargo.toml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building EverbloomSecurity Rust engine (cargo --release)"
        VERBATIM
    )
else()
    add_custom_target(engine)
    message(STATUS "Using a prebuilt Rust engine (EVERBLOOM_BUILD_ENGINE=OFF).")
endif()

set(EVERBLOOM_ENGINE_BINARY
    "${CMAKE_CURRENT_SOURCE_DIR}/engine/target/release/everbloom_engine${CMAKE_EXECUTABLE_SUFFIX}"
    CACHE FILEPATH "Prebuilt Rust engine used for staging and packaging"
)
set(EVERBLOOM_HASH_DB
    "${CMAKE_CURRENT_SOURCE_DIR}/data/local_hashes.sqlite"
)
set(EVERBLOOM_LEGACY_HASH_DB
    "${CMAKE_CURRENT_SOURCE_DIR}/hashdb/HashDB.db"
)
set(EVERBLOOM_AI_MODEL
    "${CMAKE_CURRENT_SOURCE_DIR}/everbloom_feature_cnn.onnx"
)
set(EVERBLOOM_AI_MODEL_FEATURES
    "${CMAKE_CURRENT_SOURCE_DIR}/features.json"
)
set(EVERBLOOM_AI_MODEL_CONTRACT
    "${CMAKE_CURRENT_SOURCE_DIR}/model_contract.json"
)
set(EVERBLOOM_DENSE_TREE_MODEL
    "${CMAKE_CURRENT_SOURCE_DIR}/artifacts/models/tree_ensemble/everbloom_dense_tree.onnx"
)
set(EVERBLOOM_DENSE_TREE_MODEL_FEATURES
    "${CMAKE_CURRENT_SOURCE_DIR}/artifacts/models/tree_ensemble/features.json"
)
set(EVERBLOOM_DENSE_TREE_MODEL_CONTRACT
    "${CMAKE_CURRENT_SOURCE_DIR}/artifacts/models/tree_ensemble/model_contract.json"
)
set(EVERBLOOM_RULES_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/data/rules"
)
set(EVERBLOOM_ALLOWLIST_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/data/allowlist.json"
)
set(EVERBLOOM_VULNERABLE_DRIVERS_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/data/vulnerable_drivers.json"
)

if(EVERBLOOM_INSTALL_PYTHON)
    add_custom_target(python_install ALL
        COMMAND ${Python3_EXECUTABLE} -m pip install -e ${CMAKE_CURRENT_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Installing EverbloomSecurity Python package in editable mode"
        VERBATIM
    )
else()
    # Keep the dependency target available for everbloom_gui while allowing
    # offline native/installer builds to skip pip build-isolation downloads.
    add_custom_target(python_install)
    message(STATUS "Skipping editable Python installation (EVERBLOOM_INSTALL_PYTHON=OFF).")
endif()

add_dependencies(everbloom_gui engine python_install)

set(EVERBLOOM_OPTIONAL_MODEL_STAGE_COMMANDS)
if(EXISTS "${EVERBLOOM_DENSE_TREE_MODEL}"
        AND EXISTS "${EVERBLOOM_DENSE_TREE_MODEL_FEATURES}"
        AND EXISTS "${EVERBLOOM_DENSE_TREE_MODEL_CONTRACT}")
    list(APPEND EVERBLOOM_OPTIONAL_MODEL_STAGE_COMMANDS
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:everbloom_gui>/models/tree_ensemble"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${EVERBLOOM_DENSE_TREE_MODEL}"
            "$<TARGET_FILE_DIR:everbloom_gui>/models/tree_ensemble"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${EVERBLOOM_DENSE_TREE_MODEL_FEATURES}"
            "$<TARGET_FILE_DIR:everbloom_gui>/models/tree_ensemble"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${EVERBLOOM_DENSE_TREE_MODEL_CONTRACT}"
            "$<TARGET_FILE_DIR:everbloom_gui>/models/tree_ensemble"
    )
else()
    message(STATUS "Optional dense tree AI model is not available; it will not be staged or packaged.")
endif()

add_custom_target(stage_engine ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:everbloom_gui>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_ENGINE_BINARY}"
        "$<TARGET_FILE_DIR:everbloom_gui>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_HASH_DB}"
        "$<TARGET_FILE_DIR:everbloom_gui>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_LEGACY_HASH_DB}"
        "$<TARGET_FILE_DIR:everbloom_gui>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_AI_MODEL}"
        "$<TARGET_FILE_DIR:everbloom_gui>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_AI_MODEL_FEATURES}"
        "$<TARGET_FILE_DIR:everbloom_gui>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_AI_MODEL_CONTRACT}"
        "$<TARGET_FILE_DIR:everbloom_gui>"
    ${EVERBLOOM_OPTIONAL_MODEL_STAGE_COMMANDS}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_ALLOWLIST_FILE}"
        "$<TARGET_FILE_DIR:everbloom_gui>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${EVERBLOOM_VULNERABLE_DRIVERS_FILE}"
        "$<TARGET_FILE_DIR:everbloom_gui>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${EVERBLOOM_RULES_DIR}"
        "$<TARGET_FILE_DIR:everbloom_gui>/data/rules"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:everbloom_gui>/tools"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/convert_onnx_for_everbloom.py"
        "$<TARGET_FILE_DIR:everbloom_gui>/tools"
    DEPENDS everbloom_gui engine
    COMMENT "Staging the EverbloomSecurity engine and local hash database"
    VERBATIM
)

if(BUILD_DRIVER AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/driver/CMakeLists.txt")
    add_subdirectory(driver)
endif()

if(BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

install(PROGRAMS "${EVERBLOOM_ENGINE_BINARY}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES "${EVERBLOOM_HASH_DB}"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/data"
)
install(FILES "${EVERBLOOM_LEGACY_HASH_DB}"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/data"
)
install(FILES
    "${EVERBLOOM_AI_MODEL}"
    "${EVERBLOOM_AI_MODEL_FEATURES}"
    "${EVERBLOOM_AI_MODEL_CONTRACT}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if(EXISTS "${EVERBLOOM_DENSE_TREE_MODEL}"
        AND EXISTS "${EVERBLOOM_DENSE_TREE_MODEL_FEATURES}"
        AND EXISTS "${EVERBLOOM_DENSE_TREE_MODEL_CONTRACT}")
    install(FILES
        "${EVERBLOOM_DENSE_TREE_MODEL}"
        "${EVERBLOOM_DENSE_TREE_MODEL_FEATURES}"
        "${EVERBLOOM_DENSE_TREE_MODEL_CONTRACT}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/models/tree_ensemble"
    )
endif()
install(DIRECTORY "${EVERBLOOM_RULES_DIR}/"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/data/rules"
)
install(FILES "${EVERBLOOM_ALLOWLIST_FILE}"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/data"
)
install(FILES "${EVERBLOOM_VULNERABLE_DRIVERS_FILE}"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/data"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tools/launch_gui.cmd"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
# Preserve the independently built native/Rust module outputs in the installer
# without modifying or relinking those binaries. These files are useful for
# deployment diagnostics and optional host integrations; the GUI/runtime files
# above remain the normal application entry points.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tools/convert_onnx_for_everbloom.py"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
)
set(EVERBLOOM_LIBEVERBLOOM_RS_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/libeverbloom_rs/target/release"
)
set(EVERBLOOM_SANDBOX_MONITOR_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/sandbox_monitor/target/release"
)
if(EXISTS "${EVERBLOOM_LIBEVERBLOOM_RS_DIR}/libeverbloom_rs.dll")
    install(FILES
        "${EVERBLOOM_LIBEVERBLOOM_RS_DIR}/libeverbloom_rs.dll"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/modules"
    )
endif()
if(EXISTS "${EVERBLOOM_LIBEVERBLOOM_RS_DIR}/libeverbloom_rs.dll.lib")
    install(FILES
        "${EVERBLOOM_LIBEVERBLOOM_RS_DIR}/libeverbloom_rs.dll.lib"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/modules"
    )
endif()
if(EXISTS "${EVERBLOOM_SANDBOX_MONITOR_DIR}/libsandbox_monitor.rlib")
    install(FILES
        "${EVERBLOOM_SANDBOX_MONITOR_DIR}/libsandbox_monitor.rlib"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/modules"
    )
endif()

set(EVERBLOOM_DRIVER_OUTPUT_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/driver"
)
install(FILES
    "${EVERBLOOM_DRIVER_OUTPUT_DIR}/everbloom_driver.sys"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/driver"
    OPTIONAL
)
install(FILES
    "${EVERBLOOM_DRIVER_OUTPUT_DIR}/everbloom_driver_stub.exe"
    "${EVERBLOOM_DRIVER_OUTPUT_DIR}/everbloom_driver_core.lib"
    "${EVERBLOOM_DRIVER_OUTPUT_DIR}/everbloom_kernel_policy_path_tests.exe"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/driver"
    OPTIONAL
)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/driver/package/everbloom_driver.inf"
    "${CMAKE_CURRENT_SOURCE_DIR}/driver/package/README.md"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/driver"
    OPTIONAL
)

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
    "${CMAKE_CURRENT_SOURCE_DIR}/docs/SANDBOX_SECURITY.md"
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
)

set(CPACK_PACKAGE_NAME "EverbloomSecurity")
set(CPACK_PACKAGE_VENDOR "EverbloomSecurity")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "EverbloomSecurity V1.0.0 cross-platform security desktop client")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_FILE_NAME "EverbloomSecurity-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "EverbloomSecurity")
set(CPACK_PACKAGE_EXECUTABLES "everbloom_gui" "EverbloomSecurity")
set(CPACK_CREATE_DESKTOP_LINKS "everbloom_gui")

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_VERSION 3)
    set(CPACK_WIX_ARCHITECTURE "x64")
    set(CPACK_WIX_INSTALL_SCOPE "perMachine")
    set(CPACK_WIX_UPGRADE_GUID "A2CD8223-686C-45E5-91F4-44F4F504D207")
    set(CPACK_WIX_PROGRAM_MENU_FOLDER "EverbloomSecurity")
    set(CPACK_WIX_ROOT_FEATURE_TITLE "EverbloomSecurity")
    set(
        CPACK_WIX_ROOT_FEATURE_DESCRIPTION
        "EverbloomSecurity antivirus desktop client, scanning engine, signatures, and runtime libraries"
    )
    # Some minimal/CI Windows images do not expose the Windows Installer
    # validation service.  Keep MSI generation deterministic there; the
    # generated package still contains the normal WiX tables and can be
    # validated on a full Windows Installer host during release QA.
    set(CPACK_WIX_LIGHT_EXTRA_FLAGS "-sval")
    if(POLICY CMP0172)
        cmake_policy(SET CMP0172 NEW)
    endif()
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
else()
    set(CPACK_GENERATOR "AppImage")
endif()

include(CPack)
