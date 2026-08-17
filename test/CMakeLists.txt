add_executable(ratchet_tests
               test_main.cpp
               test_bip39.cpp
               test_kdf.cpp
               test_vault.cpp
               test_store.cpp
               test_x3dh.cpp
               test_ratchet.cpp
               test_session.cpp
               test_message.cpp
               test_cli.cpp
               test_media.cpp
               test_secure.cpp
               test_terminal.cpp
               test_vectors.cpp)

target_link_libraries(ratchet_tests PRIVATE ratchet_core)
target_include_directories(ratchet_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(RATCHET_HARDENED AND NOT MSVC)
  target_compile_options(ratchet_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME ratchet_tests COMMAND ratchet_tests)
