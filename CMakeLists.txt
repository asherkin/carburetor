cmake_minimum_required(VERSION 2.8.0)
project(carburetor)

include(ExternalProject)
include(CheckIncludeFileCXX)

list(APPEND CMAKE_CXX_FLAGS "-std=c++11")

check_include_file_cxx(mysql/mysql.h HAS_BURIED_MYSQL)
if (HAS_BURIED_MYSQL)
  add_definitions(-DMYSQLPP_MYSQL_HEADERS_BURIED)
  list(APPEND CMAKE_REQUIRED_DEFINITIONS -DMYSQLPP_MYSQL_HEADERS_BURIED)
else()
  check_include_file_cxx(mysql.h HAS_MYSQL)
  if(NOT HAS_MYSQL)
    message(FATAL_ERROR "Failed to find MySQL C client header.")
  endif()
endif()

check_include_file_cxx(mysql++/mysql++.h HAS_MYSQLPP)
if(NOT HAS_MYSQLPP)
  message(FATAL_ERROR "Failed to find MySQL++ client header.")
endif()

ExternalProject_Add(
  beanstalk
  GIT_REPOSITORY https://github.com/deepfryed/beanstalk-client.git
  CONFIGURE_COMMAND ""
  BUILD_COMMAND $(MAKE) libbeanstalk.a
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(beanstalk SOURCE_DIR)
set(BEANSTALK_INCLUDE_DIRS ${SOURCE_DIR})

ExternalProject_Get_Property(beanstalk BINARY_DIR)
set(BEANSTALK_LIBRARIES ${BINARY_DIR}/libbeanstalk.a)

ExternalProject_Add(
  breakpad
  GIT_REPOSITORY https://chromium.googlesource.com/breakpad/breakpad.git
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
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(json SOURCE_DIR)
set(JSON_INCLUDE_DIRS ${SOURCE_DIR}/src)

find_package(ZLIB REQUIRED)

add_executable(${PROJECT_NAME} main.cpp compressed_symbol_supplier.cpp repo_source_line_resolver.cc)
add_dependencies(${PROJECT_NAME} beanstalk breakpad json)
target_include_directories(${PROJECT_NAME} PRIVATE ${BEANSTALK_INCLUDE_DIRS} ${BREAKPAD_INCLUDE_DIRS} ${JSON_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE mysqlpp ${BEANSTALK_LIBRARIES} ${BREAKPAD_LIBRARIES} ${ZLIB_LIBRARIES})
