// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// dfab entry point.

#include <cstddef>
#include <string>
#include <vector>

#include "cli.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  if (argc > 1) {
    arguments.reserve(static_cast<std::size_t>(argc - 1));
  }
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  return decommissioning_fabric::cli::Run(arguments);
}
