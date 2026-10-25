# The desktop GUI is a process wrapper around the ratchet-usb binary: it never
# links ratchet_core and never touches the vault format. Qt6 is only needed for
# this target, so a missing Qt6 is a warning rather than a broken build of the
# CLI and its tests.
find_package(Qt6 COMPONENTS Widgets QUIET)
if(NOT Qt6Widgets_FOUND)
  message(WARNING
          "Qt6 Widgets not found: the ratchet-gui target will not be built. "
          "Install the Qt6 base development package (e.g. qt6-qtbase-devel) "
          "and reconfigure.")
  return()
endif()

set(CMAKE_AUTOMOC ON)

add_executable(ratchet-gui
               main.cpp
               main_window.cpp
               main_window.hpp
               cli_runner.cpp
               cli_runner.hpp
               host_env.cpp
               host_env.hpp)

target_link_libraries(ratchet-gui PRIVATE Qt6::Widgets)

if(RATCHET_HARDENED AND NOT MSVC)
  # Same hardening as ratchet-usb. The GUI parses no key material, but it does
  # hold the passphrase and received payloads in its own address space, so it
  # gets the stack protector and full RELRO too rather than only PIE.
  target_compile_options(ratchet-gui PRIVATE -Wall -Wextra -Wpedantic
                         -fstack-protector-strong -fPIE)
  if(NOT WIN32)
    target_link_options(ratchet-gui PRIVATE -pie -Wl,-z,relro,-z,now)
  endif()
endif()

install(TARGETS ratchet-gui RUNTIME DESTINATION bin)
