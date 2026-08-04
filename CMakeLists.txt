cmake_minimum_required(VERSION 3.18)
project(pisat VERSION 0.1.0 LANGUAGES CXX)

option(PISAT_BUILD_TESTS "Build PiSAT tests" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(pisat_core
    src/pisat.cpp
)
target_include_directories(pisat_core PUBLIC include)
target_compile_options(pisat_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

if(UNIX)
    find_package(Threads REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_path(PIGPIO_INCLUDE_DIR pigpio.h REQUIRED)
    find_library(PIGPIO_LIBRARY pigpio REQUIRED)
    find_library(RT_LIBRARY rt REQUIRED)
    target_include_directories(pisat_core PRIVATE ${PIGPIO_INCLUDE_DIR})
    target_link_libraries(pisat_core PUBLIC
        Threads::Threads OpenSSL::Crypto ${PIGPIO_LIBRARY} ${RT_LIBRARY})
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(pisat_core PUBLIC OpenSSL::Crypto)
endif()

add_executable(pisat src/main.cpp)
target_link_libraries(pisat PRIVATE pisat_core)

include(GNUInstallDirs)
install(TARGETS pisat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES config/pisat.conf DESTINATION /etc/pisat
    PERMISSIONS OWNER_READ OWNER_WRITE)
install(FILES packaging/pisat.service DESTINATION /etc/systemd/system)

if(PISAT_BUILD_TESTS)
    enable_testing()
    add_executable(pisat_tests tests/test_parser.cpp)
    target_link_libraries(pisat_tests PRIVATE pisat_core)
    add_test(NAME pisat_tests COMMAND pisat_tests)
endif()
