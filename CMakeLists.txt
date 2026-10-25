cmake_minimum_required(VERSION 3.16)
project(darcraw CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Header-only core library. The back-end a developer extends lives in include/darcraw.
add_library(darcraw INTERFACE)
target_include_directories(darcraw INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(darcraw INTERFACE OpenSSL::Crypto Threads::Threads)

enable_testing()
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/test_*.cpp)
foreach(src ${TEST_SOURCES})
  get_filename_component(name ${src} NAME_WE)
  add_executable(${name} ${src})
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
  target_link_libraries(${name} PRIVATE darcraw)
  add_test(NAME ${name} COMMAND ${name})
endforeach()

# sam_check validates the SAM transport against a live router. It is built but not run
# as a test, since it needs an I2P SAM bridge on 127.0.0.1:7656.
add_executable(sam_check ${CMAKE_SOURCE_DIR}/tools/sam_check.cpp)
target_link_libraries(sam_check PRIVATE darcraw)
