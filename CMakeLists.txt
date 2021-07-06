project(h2isto)

cmake_minimum_required(VERSION 3.10)

include(ExternalProject)

enable_testing()


function(generateDepsTargets)
    ExternalProject_Add(
            gtest
            PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/gtest
            GIT_REPOSITORY https://github.com/google/googletest.git
            UPDATE_COMMAND git checkout release-1.7.0
            CONFIGURE_COMMAND ""
            BUILD_COMMAND rm -rf build && mkdir build && cd build && cmake .. && make
            INSTALL_COMMAND ""
            BUILD_IN_SOURCE 1
    )

    set(GTEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/gtest/src/gtest)
    set(GTEST_LIB_DIR ${GTEST_DIR}/build PARENT_SCOPE)
    set(GTEST_INC_DIR ${GTEST_DIR}/include PARENT_SCOPE)
endfunction()


function(generateMain)
    add_executable(h2isto Main.cpp)
endfunction()

function(generateUnitTestTargets)
    message("gtest include dir will be ${GTEST_INC_DIR}")
    add_executable(utests utests/UTests.cpp)
    target_include_directories(utests PRIVATE ${GTEST_INC_DIR})
    target_link_libraries(utests PRIVATE
            ${GTEST_LIB_DIR}/libgtest_main.a
            ${GTEST_LIB_DIR}/libgtest.a
            pthread)
endfunction()

function(Main)
    generateDepsTargets()
    generateUnitTestTargets()
    generateMain()
endfunction()

Main()