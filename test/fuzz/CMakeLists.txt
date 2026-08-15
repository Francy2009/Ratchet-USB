# libFuzzer targets. Off by default and clang-only: -fsanitize=fuzzer is a
# clang feature, and GCC builds (which is what the main CI matrix and every
# `setup.sh` run use) must not trip over this directory.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
          "RATCHET_BUILD_FUZZERS requires clang (-fsanitize=fuzzer). "
          "Re-run with -DCMAKE_CXX_COMPILER=clang++.")
endif()

add_executable(fuzz_parsers fuzz_parsers.cpp)
target_link_libraries(fuzz_parsers PRIVATE ratchet_core)

# The state machine, which the parser harness cannot reach: its inputs are
# well-formed by construction, and the bugs there are about what the protocol
# does with a message rather than how it reads one.
add_executable(fuzz_session fuzz_session.cpp)
target_link_libraries(fuzz_session PRIVATE ratchet_core)
target_compile_options(fuzz_session PRIVATE ${RATCHET_FUZZ_FLAGS})
target_link_options(fuzz_session PRIVATE -fsanitize=fuzzer,address,undefined)

# The harness gets the full -fsanitize=fuzzer (it supplies main); ratchet_core
# is instrumented by the top-level CMakeLists with fuzzer-no-link, so the
# coverage feedback the fuzzer steers by actually comes from the parsers rather
# than from these forty lines.
target_compile_options(fuzz_parsers PRIVATE ${RATCHET_FUZZ_FLAGS})
target_link_options(fuzz_parsers PRIVATE -fsanitize=fuzzer,address,undefined)
