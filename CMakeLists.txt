cmake_minimum_required(VERSION 3.24)

project(DecommissioningFabric
    VERSION 1.0.0
    DESCRIPTION "DCCP governed retirement of physical facility assets"
    HOMEPAGE_URL "https://github.com/summonlabs/Decommissioning-Fabric"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(DF_BUILD_TESTS "Build the Decommissioning Fabric test suite" ${BUILD_TESTING})
option(DF_BUILD_BENCHMARKS "Build the benchmark harness" OFF)
option(DF_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(DF_ENABLE_COVERAGE "Instrument for coverage (non-MSVC, Debug/RelWithDebInfo)" OFF)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()

# ---------------------------------------------------------------------------
# Warning configuration: strict first-party warnings in every configuration.
# ---------------------------------------------------------------------------
add_library(df_project_warnings INTERFACE)
add_library(DecommissioningFabric::project_warnings ALIAS df_project_warnings)
# The warnings interface is installed and exported with the library. A static
# library's PRIVATE link to an interface target becomes a LINK_ONLY interface
# requirement of the exported target, so an unexported warnings target would
# make the package unusable by a downstream find_package consumer. Exporting it
# is also useful: a consumer can opt into exactly the strictness this library is
# built with.
set_target_properties(df_project_warnings PROPERTIES EXPORT_NAME project_warnings)

if(MSVC)
    target_compile_options(df_project_warnings INTERFACE
        /W4
        /permissive-
        /Zc:__cplusplus
        /Zc:preprocessor
        /Zc:externConstexpr
        /Zc:inline
        /EHsc
        /utf-8
        /wd4702 # unreachable code: produced by contract macros in constexpr paths
    )
    if(DF_WARNINGS_AS_ERRORS)
        target_compile_options(df_project_warnings INTERFACE /WX)
    endif()
    # Deterministic source character set and no MSVC-specific extensions leak.
    target_compile_definitions(df_project_warnings INTERFACE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE)
else()
    target_compile_options(df_project_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wcast-align
        -Wcast-qual
        -Wdouble-promotion
        -Wformat=2
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
        -Wnull-dereference
        -Wimplicit-fallthrough
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
        -Wuseless-cast
        -Wzero-as-null-pointer-constant)
    if(DF_WARNINGS_AS_ERRORS)
        target_compile_options(df_project_warnings INTERFACE -Werror)
    endif()
endif()

if(DF_ENABLE_COVERAGE AND NOT MSVC)
    target_compile_options(df_project_warnings INTERFACE --coverage -O0 -g)
    add_link_options(--coverage)
endif()

# ---------------------------------------------------------------------------
# Version / provenance stamping
# ---------------------------------------------------------------------------
find_package(Git QUIET)
set(DF_GIT_COMMIT "unknown")
set(DF_GIT_DIRTY "unknown")
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE DF_GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE DF_GIT_RESULT)
    if(NOT DF_GIT_RESULT EQUAL 0 OR DF_GIT_COMMIT STREQUAL "")
        set(DF_GIT_COMMIT "unknown")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" status --porcelain
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE DF_GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(DF_GIT_STATUS STREQUAL "")
        set(DF_GIT_DIRTY "false")
    else()
        set(DF_GIT_DIRTY "true")
    endif()
    unset(DF_GIT_STATUS)
    unset(DF_GIT_RESULT)
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(DF_PUBLIC_HEADERS
    include/decommissioning_fabric/version.hpp
    include/decommissioning_fabric/ids.hpp
    include/decommissioning_fabric/hash.hpp
    include/decommissioning_fabric/time.hpp
    include/decommissioning_fabric/errors.hpp
    include/decommissioning_fabric/lock_order.hpp
    include/decommissioning_fabric/authority.hpp
    include/decommissioning_fabric/lifecycle.hpp
    include/decommissioning_fabric/obligations.hpp
    include/decommissioning_fabric/residual.hpp
    include/decommissioning_fabric/evidence.hpp
    include/decommissioning_fabric/plan.hpp
    include/decommissioning_fabric/store.hpp
    include/decommissioning_fabric/engine.hpp
    include/decommissioning_fabric/format.hpp)

set(DF_SOURCES
    src/hash.cpp
    src/errors.cpp
    src/time.cpp
    src/authority.cpp
    src/lifecycle.cpp
    src/obligations.cpp
    src/residual.cpp
    src/evidence.cpp
    src/plan.cpp
    src/store.cpp
    src/engine.cpp
    src/engine_query.cpp
    src/serialize.cpp)

add_library(decommissioning_fabric STATIC ${DF_SOURCES} ${DF_PUBLIC_HEADERS})
add_library(DecommissioningFabric::decommissioning_fabric ALIAS decommissioning_fabric)

target_include_directories(decommissioning_fabric
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(decommissioning_fabric PUBLIC cxx_std_20)
target_link_libraries(decommissioning_fabric PRIVATE df_project_warnings)
target_compile_definitions(decommissioning_fabric
    PRIVATE DF_INTERNAL_BUILD=1
    PUBLIC DF_GIT_COMMIT="${DF_GIT_COMMIT}" DF_GIT_DIRTY="${DF_GIT_DIRTY}")

set_target_properties(decommissioning_fabric PROPERTIES
    OUTPUT_NAME "decommissioning_fabric"
    EXPORT_NAME "decommissioning_fabric"
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}")

if(MSVC)
    target_compile_options(decommissioning_fabric PRIVATE /bigobj)
endif()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
add_executable(dfab
    src/cli/main.cpp
    src/cli/command_line.cpp
    src/cli/commands.cpp
    src/cli/render.cpp)
target_link_libraries(dfab PRIVATE
    decommissioning_fabric
    df_project_warnings)
target_compile_definitions(dfab PRIVATE DF_GIT_COMMIT="${DF_GIT_COMMIT}")
set_target_properties(dfab PROPERTIES
    OUTPUT_NAME "dfab"
    INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")

# ---------------------------------------------------------------------------
# Crash-consistency / fault-injection driver (not installed)
# ---------------------------------------------------------------------------
add_executable(dfab_crash_driver tests/support/crash_driver.cpp)
target_link_libraries(dfab_crash_driver PRIVATE
    decommissioning_fabric
    df_project_warnings)
target_include_directories(dfab_crash_driver PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/support")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(DF_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(DF_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

# ---------------------------------------------------------------------------
# Install / export / package
# ---------------------------------------------------------------------------
install(TARGETS decommissioning_fabric dfab df_project_warnings
    EXPORT DecommissioningFabricTargets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(DIRECTORY include/decommissioning_fabric
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.hpp")

install(EXPORT DecommissioningFabricTargets
    FILE DecommissioningFabricTargets.cmake
    NAMESPACE DecommissioningFabric::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DecommissioningFabric")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/DecommissioningFabricConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/DecommissioningFabricConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DecommissioningFabric")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/DecommissioningFabricConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/DecommissioningFabricConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/DecommissioningFabricConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DecommissioningFabric")

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
    README.md
    DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/DecommissioningFabric")

install(DIRECTORY docs/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/DecommissioningFabric/docs"
    FILES_MATCHING PATTERN "*.md")

# ---------------------------------------------------------------------------
# CPack
# ---------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "DecommissioningFabric")
set(CPACK_PACKAGE_VENDOR "Summon Software Labs")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_CONTACT "Summon Software Labs")
set(CPACK_PACKAGE_FILE_NAME "DecommissioningFabric-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
include(CPack)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "DecommissioningFabric ${PROJECT_VERSION} (${DF_GIT_COMMIT}, dirty=${DF_GIT_DIRTY})")
message(STATUS "  build type        : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ compiler      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  warnings as errors: ${DF_WARNINGS_AS_ERRORS}")
message(STATUS "  tests             : ${DF_BUILD_TESTS}")
message(STATUS "  benchmarks        : ${DF_BUILD_BENCHMARKS}")
