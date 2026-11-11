cmake_minimum_required(VERSION 3.16)

set(PROJECT_NAME sss-webserver)
project(${PROJECT_NAME}
        LANGUAGES CXX
        VERSION 0.2.0
        DESCRIPTION "A lightweight embedded HTTP/HTTPS webserver")

include(GNUInstallDirs)

set(EXECUTABLE_NAME ${PROJECT_NAME}_executable)
set(LIBRARY_NAME ${PROJECT_NAME}_library)

set(CMAKE_INSTALL_RPATH "")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
set(CMAKE_SKIP_RPATH FALSE)
set(CMAKE_SKIP_BUILD_RPATH FALSE)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(CPPHTTPLIB_LIBRARY NAMES cpp-httplib httplib REQUIRED)
find_path(CPPHTTPLIB_INCLUDE_DIR NAMES httplib.h REQUIRED)

set(SOURCES src/mime_registry.cpp
            src/webserver.cpp)

option(SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY "Build as shared library" OFF)
option(SSS_WEBSERVER_BUILD_AS_STATIC_LIBRARY "Build as static library" OFF)
option(SSS_WEBSERVER_BUILD_EXECUTABLE "Build an executable" ON)
option(SSS_WEBSERVER_BUILD_TESTS "Build tests" ON)

if (SSS_WEBSERVER_BUILD_EXECUTABLE)
    if (NOT(SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY OR SSS_WEBSERVER_BUILD_AS_STATIC_LIBRARY))
        set(SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY ON)
        message("-- ${PROJECT_NAME}: No library type was defined so defaulting to a shared library")
    endif()
endif()

if (SSS_WEBSERVER_BUILD_EXECUTABLE)
    if (NOT(SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY OR SSS_WEBSERVER_BUILD_AS_STATIC_LIBRARY))
        set(SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY ON)
        message("-- ${PROJECT_NAME}: No library type was defined so defaulting to a shared library")
    endif()
endif()

if (SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY)
    message("-- ${PROJECT_NAME}: Building ${PROJECT_NAME} as a shared library")
    add_library(${LIBRARY_NAME} SHARED ${SOURCES})
elseif (SSS_WEBSERVER_BUILD_AS_STATIC_LIBRARY)
    message("-- ${PROJECT_NAME}: Building ${PROJECT_NAME} as a static library")
    add_library(${LIBRARY_NAME} STATIC ${SOURCES})
elseif (NOT SSS_WEBSERVER_BUILD_EXECUTABLE)
    message(FATAL_ERROR "${PROJECT_NAME}: Nothing is configured to be built")
endif()

set_target_properties(${LIBRARY_NAME} PROPERTIES
                      OUTPUT_NAME ${PROJECT_NAME}
                      EXPORT_NAME WEBSERVER
)

target_include_directories(${LIBRARY_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_include_directories(${LIBRARY_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CPPHTTPLIB_INCLUDE_DIR}
)

target_link_libraries(${LIBRARY_NAME} PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    ${CPPHTTPLIB_LIBRARY}
)

target_compile_definitions(${LIBRARY_NAME} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_17)
target_compile_options(${LIBRARY_NAME} PRIVATE -Wall -Wextra -Wpedantic -Werror -O3)

if (SSS_WEBSERVER_BUILD_EXECUTABLE)
    message("   Building ${PROJECT_NAME} as an executable (as well)")
    add_executable(${EXECUTABLE_NAME} src/main.cpp)
    target_link_libraries(${EXECUTABLE_NAME} PRIVATE ${LIBRARY_NAME})
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE
                               SSS_WEBSERVER_VERSION_MAJOR=${${PROJECT_NAME}_VERSION_MAJOR}
                               SSS_WEBSERVER_VERSION_MINOR=${${PROJECT_NAME}_VERSION_MINOR}
                               SSS_WEBSERVER_VERSION_PATCH=${${PROJECT_NAME}_VERSION_PATCH}
    )
    set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
    target_compile_features(${EXECUTABLE_NAME} PUBLIC cxx_std_17)
    target_compile_options(${EXECUTABLE_NAME} PRIVATE -Wall -Wextra -Wpedantic -Werror -O3)

    install(TARGETS ${EXECUTABLE_NAME}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if (SSS_WEBSERVER_BUILD_AS_SHARED_LIBRARY OR SSS_WEBSERVER_BUILD_AS_STATIC_LIBRARY)
    install(TARGETS ${LIBRARY_NAME}
            EXPORT SSS_WEBSERVER_TARGETS
            DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT SSS_WEBSERVER_TARGETS
        FILE ${PROJECT_NAME}Targets.cmake
        NAMESPACE SSS::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

if (SSS_WEBSERVER_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    add_executable(webserver_test tests/webserver_test.cpp)
    target_include_directories(webserver_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_definitions(webserver_test PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
        CLI_BIN_PATH="$<TARGET_FILE:${EXECUTABLE_NAME}>"
    )
    target_link_libraries(webserver_test PRIVATE
        ${LIBRARY_NAME}
        ${CPPHTTPLIB_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        GTest::gtest_main
        Threads::Threads
    )
    target_compile_features(webserver_test PUBLIC cxx_std_17)
    target_compile_options(webserver_test PRIVATE -Wall -Wextra)
    add_test(NAME webserver_test COMMAND webserver_test)
endif()

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "media-types")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_PACKAGE_VENDOR "SSS")
set(CPACK_PACKAGE_CONTACT "Bradley Marshall")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
include(CPack)
