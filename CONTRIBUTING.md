# Contributing to Decommissioning Fabric

Decommissioning Fabric is part of the Data Center Control Plane (DCCP) and is
developed by Summon Software Labs. Contributions are welcome under the terms
below.

## License of contributions

This project is licensed under the Apache License, Version 2.0. By submitting a
contribution you agree that your contribution is licensed under the same terms,
as described in section 5 of that license: unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
shall be under the terms and conditions of the Apache License, Version 2.0,
without any additional terms or conditions.

There is **no Contributor License Agreement** and no copyright assignment. You
keep the copyright on your contribution; the project receives it under the same
license it distributes under.

If your contribution includes code you did not write, say so in the pull
request and include the origin and license of that code. Do not contribute code
you cannot license under Apache-2.0.

## Commit trailers

Do not add `Co-authored-by` trailers, sign-off lines, or any other trailer that
names someone who did not author the change. Commit messages must be concise,
neutral, and public-facing. Describe the change, not the process that produced
it, and do not mention internal tooling, prompts, harnesses, or workflow rules.

## Code quality expectations

The bar for a change is the same as the bar for the repository:

* **C++20**, standard library first. A new third-party dependency needs a
  compelling systems reason; the default answer is no.
* **Zero first-party warnings.** The build uses `/W4 /WX` on MSVC. Do not
  suppress a warning to make it go away; fix the cause or explain precisely why
  the warning is wrong in a comment at the suppression site.
* **Vendor neutral.** No vendor-specific behaviour, no vendor names in the
  domain model, no hidden credentials, no machine specific absolute paths, no
  development-only URLs.
* **No telemetry.** The runtime transmits nothing, ever.
* **Doctrine over convenience.** Observation is not authority, acknowledgement
  is not effect, requested state is not observed state, and missing or unknown
  is never silently turned into zero, false, healthy, ready, safe, or permitted.
  A change that makes an unknown value look benign will be rejected.

## Build and test

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Build both `Release` and `Debug`. Debug enables the lock-order validator, which
aborts on a lock-order inversion; a change that trips it is a defect in the
change, not in the validator.

## Tests are proof obligations

A change that claims behaviour must come with a test that would fail without it.
Prefer, in rough order of strength:

1. a property or seeded state-machine test with a deterministic seed;
2. an adversarial test over malformed, truncated, or corrupt input;
3. a real cross-process or crash-consistency test;
4. an integration test through the public API;
5. a unit test.

Do not substitute a mock for something that can be tested directly on the host.
Do not claim distributed behaviour from threads alone. If a claim depends on
physical data-centre hardware, label it SYNTHETIC and keep process, filesystem,
durability, and packaging claims labelled REAL.

## Never use timeouts

Tests run to completion. A hanging test is a defect to diagnose and fix, not a
condition to time out of. Do not add timeouts, watchdogs, or retry-until-green
loops to the test suite.

## Reporting a problem

Open an issue with the exact command, the exact observed output, and the exact
expected output. If the problem involves durable state, include the store
directory listing and the `dfab store status` output. Do not attach a store
directory that contains real facility data.
