cmake_minimum_required(VERSION 3.16)

project(ratchet-usb
        VERSION 0.2.0
        DESCRIPTION "Encrypted seed vault for over-the-top messaging"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(RATCHET_BUILD_TESTS "Build the unit tests" ON)
option(RATCHET_HARDENED "Enable hardening flags" ON)
option(RATCHET_BUILD_FUZZERS "Build the libFuzzer targets (clang only)" OFF)

# Shared by ratchet_core and the harnesses, so the library the fuzzer explores
# and the harness driving it agree on their sanitizer runtimes -- mixing them
# links but misreports.
set(RATCHET_FUZZ_FLAGS
    -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)

# --- libsodium -------------------------------------------------------------
# The only crypto dependency. pkg-config first, then a manual search so the
# build also works against a libsodium installed by hand on the USB toolchain.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
endif()

if(TARGET PkgConfig::SODIUM)
  add_library(sodium::sodium ALIAS PkgConfig::SODIUM)
else()
  find_path(SODIUM_INCLUDE_DIR sodium.h)
  find_library(SODIUM_LIBRARY NAMES sodium libsodium)
  if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR
            "libsodium not found. Install libsodium-dev / libsodium, or point "
            "CMAKE_PREFIX_PATH at your libsodium installation.")
  endif()
  add_library(sodium::sodium UNKNOWN IMPORTED)
  set_target_properties(sodium::sodium PROPERTIES
                        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
                        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
endif()

# crypto_kdf_hkdf_sha256_* landed in libsodium 1.0.19. On older releases the
# project compiles its own RFC 5869 HKDF on top of crypto_auth_hmacsha256; the
# two are byte-compatible and both are checked against the RFC test vectors.
include(CheckCXXSourceCompiles)
include(CMakePushCheckState)
cmake_push_check_state()
if(TARGET PkgConfig::SODIUM)
  set(CMAKE_REQUIRED_INCLUDES ${SODIUM_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${SODIUM_LIBRARIES})
  set(CMAKE_REQUIRED_LINK_OPTIONS ${SODIUM_LDFLAGS})
else()
  set(CMAKE_REQUIRED_INCLUDES ${SODIUM_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${SODIUM_LIBRARY})
endif()
# A feature check must answer "does this symbol exist", and nothing else. It
# inherits CMAKE_CXX_FLAGS, so without this a warning-as-error build turns any
# diagnostic in the snippet below into "feature absent" -- and the failure is
# silent: the build simply uses the bundled HKDF and prints a status line. That
# is exactly what -Werror plus the nonnull arguments this snippet used to pass
# did. Suppressing -Werror for the check keeps a future warning from quietly
# reconfiguring the crypto.
if(NOT MSVC)
  set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Wno-error")
endif()
check_cxx_source_compiles("
#include <sodium.h>
int main() {
  unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
  unsigned char ikm[32] = {0};
  unsigned char okm[32];
  crypto_kdf_hkdf_sha256_extract(prk, ikm, sizeof ikm, ikm, sizeof ikm);
  return crypto_kdf_hkdf_sha256_expand(okm, sizeof okm, \"\", 0, prk);
}
" RATCHET_HAVE_SODIUM_HKDF)
cmake_pop_check_state()

# --- library ---------------------------------------------------------------
add_library(ratchet_core
            src/secure.cpp
            src/bip39.cpp
            src/bip39_wordlist.cpp
            src/kdf.cpp
            src/x25519.cpp
            src/identity.cpp
            src/prekey.cpp
            src/wire.cpp
            src/store.cpp
            src/message.cpp
            src/x3dh.cpp
            src/ratchet.cpp
            src/session.cpp
            src/vault.cpp
            src/terminal.cpp
            src/media.cpp
            src/cli.cpp
            src/app.cpp)

target_include_directories(ratchet_core PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ratchet_core PUBLIC sodium::sodium)

if(RATCHET_HAVE_SODIUM_HKDF)
  target_compile_definitions(ratchet_core PUBLIC RATCHET_HAVE_SODIUM_HKDF)
else()
  message(STATUS
          "libsodium has no crypto_kdf_hkdf_sha256_*; using the built-in "
          "RFC 5869 HKDF-SHA256 (libsodium >= 1.0.19 is recommended)")
endif()

if(RATCHET_HARDENED AND NOT MSVC)
  target_compile_options(ratchet_core PRIVATE
                         -Wall -Wextra -Wpedantic -Wshadow -Wconversion
                         -fstack-protector-strong)
  # Bounds-checked forms of the libc calls the compiler can prove the size of.
  # This says nothing about core dumps, whatever an earlier version of this
  # comment claimed -- keeping secrets out of a dump is a run-time matter, and
  # it is harden_process() in src/secure.cpp that does it.
  target_compile_definitions(ratchet_core PRIVATE _FORTIFY_SOURCE=2)
endif()

# Instrument the library itself, not just the harness: libFuzzer steers by
# coverage, and coverage it cannot see is code it will not explore.
if(RATCHET_BUILD_FUZZERS)
  target_compile_options(ratchet_core PUBLIC
                         -fsanitize=fuzzer-no-link,address,undefined
                         -fno-omit-frame-pointer -g)
  target_link_options(ratchet_core PUBLIC -fsanitize=address,undefined)
endif()

# --- executable ------------------------------------------------------------
add_executable(ratchet-usb src/main.cpp)
target_link_libraries(ratchet-usb PRIVATE ratchet_core)
if(RATCHET_HARDENED AND NOT MSVC)
  target_compile_options(ratchet-usb PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- tests -----------------------------------------------------------------
if(RATCHET_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

if(RATCHET_BUILD_FUZZERS)
  add_subdirectory(test/fuzz)
endif()

install(TARGETS ratchet-usb RUNTIME DESTINATION bin)
