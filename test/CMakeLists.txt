add_executable(ratchet_tests
               test_main.cpp
               test_bip39.cpp
               test_passphrase.cpp
               test_kdf.cpp
               test_vault.cpp
               test_store.cpp
               test_x3dh.cpp
               test_pq.cpp
               test_rollback.cpp
               test_ratchet.cpp
               test_triple_ratchet.cpp
               test_spqr.cpp
               test_session.cpp
               test_message.cpp
               test_cli.cpp
               test_media.cpp
               test_file.cpp
               test_secure.cpp
               test_terminal.cpp
               test_screen.cpp
               test_ui.cpp
               test_vectors.cpp
               test_kat.cpp)

target_link_libraries(ratchet_tests PRIVATE ratchet_core)
target_include_directories(ratchet_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(RATCHET_HARDENED AND NOT MSVC)
  target_compile_options(ratchet_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME ratchet_tests COMMAND ratchet_tests)

# The GUI's host-environment cleanup is what makes "Apri cartella" work from the
# AppImage. It only needs QtCore, so test it whenever Qt6 Test is available,
# even in builds that do not build the rest of the GUI.
find_package(Qt6 COMPONENTS Test QUIET)
if(Qt6Test_FOUND)
  add_executable(ratchet_gui_tests
                 test_host_env.cpp
                 ${CMAKE_SOURCE_DIR}/gui/host_env.cpp)
  set_target_properties(ratchet_gui_tests PROPERTIES AUTOMOC ON)
  target_include_directories(ratchet_gui_tests PRIVATE
                             ${CMAKE_SOURCE_DIR}/gui
                             ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(ratchet_gui_tests PRIVATE Qt6::Core Qt6::Test)
  add_test(NAME ratchet_gui_tests COMMAND ratchet_gui_tests)
endif()
