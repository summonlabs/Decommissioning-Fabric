# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Test suite. Every target here is a proof obligation: each one exists to
# establish a specific claim made in the README and ARCHITECTURE, and each is
# registered with CTest under the label naming the claim class.

set(DF_UNIT_TESTS
    unit/test_ids.cpp
    unit/test_hash.cpp
    unit/test_time.cpp
    unit/test_errors.cpp
    unit/test_format.cpp
    unit/test_lifecycle.cpp
    unit/test_authority.cpp
    unit/test_residual.cpp
    unit/test_fence.cpp)

set(DF_INTEGRATION_TESTS
    integration/test_engine_flow.cpp
    integration/test_validation_precedence.cpp
    integration/test_state_machine.cpp)

set(DF_ADVERSARIAL_TESTS
    adversarial/test_adversarial.cpp)

set(DF_DURABILITY_TESTS
    durability/test_durability.cpp
    durability/test_multiprocess.cpp)

set(DF_CONCURRENCY_TESTS
    concurrency/test_concurrency.cpp)

set(DF_E2E_TESTS
    e2e/test_cli.cpp)

# support/ is on the include path for every test target in this directory.
include_directories("support")

function(df_add_test target source label)
    add_executable(${target} "${source}")
    target_link_libraries(${target} PRIVATE decommissioning_fabric df_project_warnings)
    add_test(NAME ${target} COMMAND ${target})
    set_tests_properties(${target} PROPERTIES LABELS "${label}")
endfunction()

foreach(source IN LISTS DF_UNIT_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "unit")
endforeach()

foreach(source IN LISTS DF_INTEGRATION_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "integration")
endforeach()

foreach(source IN LISTS DF_ADVERSARIAL_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "adversarial")
endforeach()

foreach(source IN LISTS DF_DURABILITY_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "durability")
    target_compile_definitions("${name}" PRIVATE
        DF_CRASH_DRIVER_PATH="$<TARGET_FILE:dfab_crash_driver>"
        DF_CLI_PATH="$<TARGET_FILE:dfab>")
endforeach()

foreach(source IN LISTS DF_CONCURRENCY_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "concurrency")
endforeach()

foreach(source IN LISTS DF_E2E_TESTS)
    get_filename_component(name "${source}" NAME_WE)
    df_add_test("${name}" "${source}" "e2e")
    target_compile_definitions("${name}" PRIVATE DF_CLI_PATH="$<TARGET_FILE:dfab>")
endforeach()
