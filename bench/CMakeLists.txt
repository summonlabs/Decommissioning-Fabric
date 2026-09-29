# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Benchmark harness. Built only when DF_BUILD_BENCHMARKS is ON; never installed.

add_executable(dfab_bench dfab_bench.cpp)
target_link_libraries(dfab_bench PRIVATE decommissioning_fabric df_project_warnings)
set_target_properties(dfab_bench PROPERTIES OUTPUT_NAME "dfab_bench")
