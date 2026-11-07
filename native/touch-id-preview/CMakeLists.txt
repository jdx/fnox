cmake_minimum_required(VERSION 3.25)
project(fnox_touch_id_preview LANGUAGES CXX)
option(FNOX_PORTABLE_PREVIEW "Build the opaque Qt preview on macOS for development" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OBJCXX_STANDARD 23)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_OBJCXX_EXTENSIONS OFF)

find_program(NODE_EXECUTABLE node REQUIRED)
execute_process(
  COMMAND "${NODE_EXECUTABLE}" --version
  OUTPUT_VARIABLE NODE_VERSION_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE NODE_VERSION_RESULT
)
if(NOT NODE_VERSION_RESULT EQUAL 0)
  message(FATAL_ERROR "Could not determine the Node.js version from ${NODE_EXECUTABLE}")
endif()
include("${CMAKE_CURRENT_LIST_DIR}/node-version-check.cmake")
fnox_require_typescript_node("${NODE_VERSION_OUTPUT}" "${NODE_EXECUTABLE}")
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(FINGERPRINT_HEADER "${GENERATED_DIR}/fingerprint-animation.generated.h")
add_custom_command(
  OUTPUT "${FINGERPRINT_HEADER}"
  BYPRODUCTS "${GENERATED_DIR}/theme.generated.h"
             "${GENERATED_DIR}/detail-copy-icons.generated.h"
  COMMAND "${NODE_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/build-header.mts" "${GENERATED_DIR}"
  DEPENDS
    build-header.mts animation.mts native.mts theme.mts color.mts
    assets/geometry.svg assets/flow.json assets/copy.svg assets/check.svg assets/logo.svg
  VERBATIM
)
add_custom_target(fnox-touch-id-preview-fingerprint DEPENDS "${FINGERPRINT_HEADER}")

if(NOT APPLE OR FNOX_PORTABLE_PREVIEW)
  set(CMAKE_AUTOMOC ON)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Svg)
  add_executable(fnox-touch-id-preview EXCLUDE_FROM_ALL
    portable/main.cpp portable/authorization_simulate.cpp)
  if(WIN32)
    target_sources(fnox-touch-id-preview PRIVATE portable/authorization_windows.cpp)
    target_link_libraries(fnox-touch-id-preview PRIVATE windowsapp)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Qt6 REQUIRED COMPONENTS DBus)
    target_sources(fnox-touch-id-preview PRIVATE portable/authorization_linux.cpp)
    target_link_libraries(fnox-touch-id-preview PRIVATE Qt6::DBus)
  else()
    target_sources(fnox-touch-id-preview PRIVATE portable/authorization_macos.cpp)
  endif()
  target_include_directories(fnox-touch-id-preview PRIVATE "${GENERATED_DIR}")
  target_link_libraries(fnox-touch-id-preview PRIVATE Qt6::Widgets Qt6::Svg)
  qt_add_resources(fnox-touch-id-preview preview_assets
    PREFIX "/fnox-preview" BASE assets FILES assets/logo.svg assets/geometry.svg assets/check.svg)
  add_dependencies(fnox-touch-id-preview fnox-touch-id-preview-fingerprint)
  enable_testing()
  add_test(NAME preview-smoke COMMAND fnox-touch-id-preview --smoke-test)
  set_tests_properties(preview-smoke PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FNOX_PREVIEW_AUTH=simulate")
  add_test(NAME reject-system-smoke COMMAND fnox-touch-id-preview --smoke-test)
  set_tests_properties(reject-system-smoke PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FNOX_PREVIEW_AUTH=system" WILL_FAIL TRUE)
  add_test(NAME reject-invalid-auth COMMAND fnox-touch-id-preview --smoke-test)
  set_tests_properties(reject-invalid-auth PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FNOX_PREVIEW_AUTH=invalid" WILL_FAIL TRUE)
  return()
endif()

enable_language(OBJCXX)
add_executable(fnox-touch-id-preview MACOSX_BUNDLE EXCLUDE_FROM_ALL
  preview/approval.mm
  preview/authorization.mm
  src/approval-prompt.mm
  src/fingerprint-view.mm
)
add_dependencies(fnox-touch-id-preview fnox-touch-id-preview-fingerprint)
target_include_directories(fnox-touch-id-preview PRIVATE
  src "${GENERATED_DIR}"
)
target_compile_options(fnox-touch-id-preview PRIVATE
  $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
)
target_link_libraries(fnox-touch-id-preview PRIVATE
  "-framework AppKit"
  "-framework Foundation"
  "-framework LocalAuthentication"
  "-framework QuartzCore"
  "-framework Security"
)
set_target_properties(fnox-touch-id-preview PROPERTIES
  MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist"
  MACOSX_BUNDLE_BUNDLE_NAME "Fnox Touch ID Preview"
  MACOSX_BUNDLE_GUI_IDENTIFIER "dev.jdx.fnox.touchid-preview"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1"
)
