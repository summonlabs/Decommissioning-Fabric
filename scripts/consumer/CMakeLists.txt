# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Independent out-of-tree consumer of the INSTALLED Decommissioning Fabric
# package. It is deliberately not part of this repository's own build: it exists
# to prove that a downstream project can find, link, and exercise the installed
# artifact through find_package alone.

cmake_minimum_required(VERSION 3.24)

project(DecommissioningFabricConsumer
    VERSION 1.0.0
    DESCRIPTION "Out-of-tree consumer of the installed Decommissioning Fabric package"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(DecommissioningFabric 1.0 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE DecommissioningFabric::decommissioning_fabric)

if(MSVC)
    target_compile_options(consumer PRIVATE /W4 /WX /permissive- /Zc:__cplusplus /EHsc)
else()
    target_compile_options(consumer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

message(STATUS "consumer: found DecommissioningFabric ${DecommissioningFabric_VERSION}")
message(STATUS "consumer: imported target DecommissioningFabric::decommissioning_fabric")
