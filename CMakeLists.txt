cmake_minimum_required(VERSION 3.1.0)
project(carburetor)

include(ExternalProject)
include(CheckIncludeFileCXX)

set(CMAKE_CXX_STANDARD 17)

file(GLOB BREAKPAD_PATCHES ${CMAKE_CURRENT_LIST_DIR}/patches/*.patch)

ExternalProject_Add(
  breakpad
  GIT_REPOSITORY https://chromium.googlesource.com/breakpad/breakpad.git
  UPDATE_COMMAND ""
  PATCH_COMMAND git reset --hard origin/master && git config user.name patches && git config user.email patches@localhost && git am -3 ${BREAKPAD_PATCHES}
  CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
  BUILD_COMMAND $(MAKE) src/libbreakpad.a src/third_party/libdisasm/libdisasm.a
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(breakpad SOURCE_DIR)
set(BREAKPAD_INCLUDE_DIRS ${SOURCE_DIR}/src)

ExternalProject_Get_Property(breakpad BINARY_DIR)
set(BREAKPAD_LIBRARIES ${BINARY_DIR}/src/libbreakpad.a ${BINARY_DIR}/src/third_party/libdisasm/libdisasm.a)

ExternalProject_Add(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  UPDATE_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(json SOURCE_DIR)
set(JSON_INCLUDE_DIRS ${SOURCE_DIR}/include)

ExternalProject_Add(
  codec
  GIT_REPOSITORY https://github.com/tplgy/cppcodec.git
  UPDATE_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(codec SOURCE_DIR)
set(CODEC_INCLUDE_DIRS ${SOURCE_DIR}/cppcodec)

ExternalProject_Add(
  distorm
  GIT_REPOSITORY https://github.com/gdabah/distorm.git
  UPDATE_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND $(MAKE) -C make/linux/
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(distorm SOURCE_DIR)
set(DISTORM_INCLUDE_DIRS ${SOURCE_DIR}/include)

ExternalProject_Get_Property(distorm BINARY_DIR)
set(DISTORM_LIBRARIES ${BINARY_DIR}/distorm3.a)

find_package(ZLIB REQUIRED)

add_executable(${PROJECT_NAME} main.cpp compressed_symbol_supplier.cpp repo_source_line_resolver.cc)
add_dependencies(${PROJECT_NAME} breakpad json codec distorm)
target_include_directories(${PROJECT_NAME} PRIVATE ${BREAKPAD_INCLUDE_DIRS} ${JSON_INCLUDE_DIRS} ${CODEC_INCLUDE_DIRS} ${DISTORM_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${BREAKPAD_LIBRARIES} ${DISTORM_LIBRARIES} ${ZLIB_LIBRARIES})
