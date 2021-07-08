project(h2isto)

cmake_minimum_required(VERSION 3.10)

include(ExternalProject)

enable_testing()

set (CMAKE_CXX_STANDARD 11)


function(generateDepsTargets)
    ExternalProject_Add(
            libgtest
            PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/libgtest
            GIT_REPOSITORY https://github.com/google/googletest.git
            UPDATE_COMMAND git checkout release-1.7.0
            CONFIGURE_COMMAND ""
            BUILD_COMMAND rm -rf build && mkdir build && cd build && cmake .. && make
            INSTALL_COMMAND ""
            BUILD_IN_SOURCE 1
    )
    set(GTEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/libgtest/src/libgtest)
    set(GTEST_LIB_DIR ${GTEST_DIR}/build PARENT_SCOPE)
    set(GTEST_INC_DIR ${GTEST_DIR}/include PARENT_SCOPE)


    ExternalProject_Add(
            libpcap
            PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/libpcap
            GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
            UPDATE_COMMAND git checkout libpcap-1.10.0
            CONFIGURE_COMMAND ./configure --disable-dbus --disable-usb --disable-bluetooth
            BUILD_COMMAND make
            INSTALL_COMMAND ""
            BUILD_IN_SOURCE 1
    )
    set(LIBPCAP_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/libpcap/src/libpcap)
    set(LIBPCAP_LIB_DIR ${LIBPCAP_DIR} PARENT_SCOPE)
    set(LIBPCAP_INC_DIR ${LIBPCAP_DIR} PARENT_SCOPE)


    ExternalProject_Add(
            libglog
            PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/libglog
            GIT_REPOSITORY https://github.com/google/glog
            UPDATE_COMMAND git checkout v0.5.0
            CONFIGURE_COMMAND ""
            BUILD_COMMAND rm -rf build && mkdir build && cd build && cmake .. && make
            INSTALL_COMMAND ""
            BUILD_IN_SOURCE 1
    )
    set(LIBGLOG_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/libglog/src/libglog)
    set(LIBGLOG_LIB_DIR ${LIBGLOG_DIR}/build PARENT_SCOPE)
    set(LIBGLOG_INC_DIR ${LIBGLOG_DIR}/build ${LIBGLOG_DIR}/src PARENT_SCOPE)


    add_custom_target(clean-deps
            COMMAND bash -c "rm -rf deps"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "clean deps"
            VERBATIM
    )

    add_custom_target(deps)
    add_dependencies(deps libgtest libpcap libglog)


endfunction()


function(generateMain)
    add_executable(h2isto Main.cpp ${SRC_LIST})

    target_include_directories(h2isto PRIVATE
            ${GTEST_INC_DIR}
            ${LIBPCAP_INC_DIR}
            ${LIBGLOG_INC_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(h2isto PRIVATE
            ${LIBPCAP_LIB_DIR}/libpcap.a
            ${LIBGLOG_LIB_DIR}/libglog.so
            pthread)
endfunction()

function(generateUnitTestTargets)
    add_executable(utests utests/UTests.cpp ${SRC_LIST})
    target_include_directories(utests PRIVATE
            ${GTEST_INC_DIR}
            ${LIBPCAP_INC_DIR}
            ${LIBGLOG_INC_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(utests PRIVATE
            ${GTEST_LIB_DIR}/libgtest_main.a
            ${GTEST_LIB_DIR}/libgtest.a
            ${LIBPCAP_LIB_DIR}/libpcap.a
            pthread)
endfunction()

function(Main)

    #common files for utests and binary
    set(SRC_LIST stats/stats.h plot/plot.h adq/adq.h stats/stats.cpp plot/plot.cpp adq/adq.cpp)

    generateDepsTargets()
    generateUnitTestTargets()
    generateMain()
endfunction()

Main()