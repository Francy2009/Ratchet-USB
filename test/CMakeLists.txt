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
               test_gui_format.cpp
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

  # The GUI's stdin framing helper: the plaintext must reach the CLI as exact
  # bytes on a pipe, never as an argv value.
  add_executable(ratchet_gui_payload_tests
                 test_payload_input.cpp
                 ${CMAKE_SOURCE_DIR}/gui/payload_input.cpp)
  set_target_properties(ratchet_gui_payload_tests PROPERTIES AUTOMOC ON)
  target_include_directories(ratchet_gui_payload_tests PRIVATE
                             ${CMAKE_SOURCE_DIR}/gui
                             ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(ratchet_gui_payload_tests PRIVATE Qt6::Core Qt6::Test)
  add_test(NAME ratchet_gui_payload_tests COMMAND ratchet_gui_payload_tests)

  # The structured-output parser runs in the GUI process and must reject a
  # missing, incomplete or malformed block rather than show a partial phrase.
  add_executable(ratchet_gui_output_tests
                 test_gui_output.cpp
                 ${CMAKE_SOURCE_DIR}/gui/gui_output.cpp
                 ${CMAKE_SOURCE_DIR}/gui/gui_output.hpp)
  set_target_properties(ratchet_gui_output_tests PROPERTIES AUTOMOC ON)
  target_include_directories(ratchet_gui_output_tests PRIVATE
                             ${CMAKE_SOURCE_DIR}/gui
                             ${CMAKE_SOURCE_DIR}/include
                             ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(ratchet_gui_output_tests PRIVATE Qt6::Core Qt6::Test)
  add_test(NAME ratchet_gui_output_tests COMMAND ratchet_gui_output_tests)

  # The real window against a fake CLI: verifies the message is written to
  # stdin and is not present in the child's argv. Needs Widgets and an
  # offscreen platform plugin, so it is skipped on a no-GUI build.
  find_package(Qt6 COMPONENTS Widgets QUIET)
  if(Qt6Widgets_FOUND)
    add_executable(ratchet_gui_launch_tests
                   test_gui_launch.cpp
                   ${CMAKE_SOURCE_DIR}/gui/main_window.cpp
                   ${CMAKE_SOURCE_DIR}/gui/main_window.hpp
                   ${CMAKE_SOURCE_DIR}/gui/cli_runner.cpp
                   ${CMAKE_SOURCE_DIR}/gui/cli_runner.hpp
                   ${CMAKE_SOURCE_DIR}/gui/host_env.cpp
                   ${CMAKE_SOURCE_DIR}/gui/host_env.hpp
                   ${CMAKE_SOURCE_DIR}/gui/payload_input.cpp
                   ${CMAKE_SOURCE_DIR}/gui/payload_input.hpp
                   ${CMAKE_SOURCE_DIR}/gui/gui_output.cpp
                   ${CMAKE_SOURCE_DIR}/gui/gui_output.hpp)
    set_target_properties(ratchet_gui_launch_tests PROPERTIES AUTOMOC ON)
    target_include_directories(ratchet_gui_launch_tests PRIVATE
                               ${CMAKE_SOURCE_DIR}/gui
                               ${CMAKE_SOURCE_DIR}/include
                               ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(ratchet_gui_launch_tests PRIVATE
                          Qt6::Widgets Qt6::Test)
    add_test(NAME ratchet_gui_launch_tests COMMAND ratchet_gui_launch_tests)
    set_tests_properties(ratchet_gui_launch_tests PROPERTIES
                         ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
  endif()
endif()
