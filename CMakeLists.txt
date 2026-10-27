cmake_minimum_required(VERSION 3.20)
project(tamperlog CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(monocypher STATIC
  third_party/monocypher/monocypher.c
  third_party/monocypher/monocypher-ed25519.c)
target_include_directories(monocypher PUBLIC third_party/monocypher)

add_library(tamperlog STATIC
  src/sha256.cpp src/hash.cpp src/tree.cpp src/verify.cpp src/sth.cpp)
target_include_directories(tamperlog PUBLIC include)
target_link_libraries(tamperlog PUBLIC monocypher)
target_compile_options(tamperlog PRIVATE -Wall -Wextra)

add_executable(tamperlog-cli cli/main.cpp)
set_target_properties(tamperlog-cli PROPERTIES OUTPUT_NAME tamperlog)
target_link_libraries(tamperlog-cli tamperlog)

add_executable(tests tests/tests.cpp)
target_include_directories(tests PRIVATE third_party)
target_link_libraries(tests tamperlog)
target_compile_definitions(tests PRIVATE VECTORS_DIR="${CMAKE_SOURCE_DIR}/tests/vectors")

add_executable(attacks attacks/attacks.cpp)
target_link_libraries(attacks tamperlog)

add_executable(bench bench/bench.cpp)
target_link_libraries(bench tamperlog)

add_executable(fork_sim sim/fork_sim.cpp)
target_link_libraries(fork_sim tamperlog)
