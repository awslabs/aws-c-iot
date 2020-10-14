cmake_minimum_required(VERSION 3.1)
project(aws-c-iot)
option(BUILD_IOT_DEPS "Builds aws common runtime dependencies as part of build, only do this if you don't want to control your dependency chain." OFF)

if (POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler, see AwsCFlags
endif()

if (DEFINED CMAKE_PREFIX_PATH)
    file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
endif()

if (DEFINED CMAKE_INSTALL_PREFIX)
    file(TO_CMAKE_PATH "${CMAKE_INSTALL_PREFIX}" CMAKE_INSTALL_PREFIX)
endif()

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

# This is required in order to append /lib/cmake to each element in CMAKE_PREFIX_PATH
set(AWS_MODULE_DIR "/${CMAKE_INSTALL_LIBDIR}/cmake")
string(REPLACE ";" "${AWS_MODULE_DIR};" AWS_MODULE_PATH "${CMAKE_PREFIX_PATH}${AWS_MODULE_DIR}")
# Append that generated list to the module search path
list(APPEND CMAKE_MODULE_PATH ${AWS_MODULE_PATH})

if (BUILD_IOT_DEPS)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/aws-common-runtime/aws-c-common/cmake")

    include(AwsFindPackage)

    set(IN_SOURCE_BUILD ON)
    set(BUILD_TESTING_PREV ${BUILD_TESTING})
    set(BUILD_TESTING OFF)
    add_subdirectory(aws-common-runtime/aws-c-common)

    if (UNIX AND NOT APPLE)
        add_subdirectory(aws-common-runtime/s2n)
    endif()

    add_subdirectory(aws-common-runtime/aws-c-io)
    add_subdirectory(aws-common-runtime/aws-c-compression)
    add_subdirectory(aws-common-runtime/aws-c-http)
    add_subdirectory(aws-common-runtime/aws-c-mqtt)
    set(BUILD_TESTING ${BUILD_TESTING_PREV})
else()
    include(AwsFindPackage)
    if (NOT BUILD_DEPS)
        set(IN_SOURCE_BUILD OFF)
    endif()
endif()

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(CheckCCompilerFlag)
include(AwsFindPackage)

# Platform specific includes and source

if (WIN32)
    file(GLOB AWS_IOT_OS_SRC
        "source/windows/*.c"
        )
elseif (APPLE)
    file(GLOB AWS_IOT_OS_SRC
        "source/apple/*.c"
        )
elseif (UNIX AND NOT APPLE)
    if (TARGET_ARCH MATCHES ANDROID)
        file(GLOB AWS_IOT_OS_SRC
        "source/android/*.c"
        )
    else()
        file(GLOB AWS_IOT_OS_SRC
            "source/linux/*.c"
            )
    endif()
endif()

file(GLOB AWS_IOT_HEADERS
        "include/aws/iotdevice/*.h"
        )

file(GLOB AWS_IOT_PRIV_HEADERS
        "include/aws/iotdevice/private/*.h"
        )

file(GLOB AWS_IOT_EXTERNAL_HEADERS
        "include/aws/iotdevice/external/*.h"
        )

file(GLOB AWS_IOT_SRC
        "source/*.c"
        )

file(GLOB AWS_IOT_EXTERNAL_SRC
        "source/external/*.c"
        )

file(GLOB IOT_HEADERS
        ${AWS_IOT_HEADERS}
        ${AWS_IOT_PRIV_HEADERS}
        ${AWS_IOT_EXTERNAL_HEADERS}
        )

file(GLOB IOT_SRC
        ${AWS_IOT_SRC}
        ${AWS_IOT_EXTERNAL_SRC}
        ${AWS_IOT_OS_SRC}
        ${AWS_IOT_PRIV_HEADERS}
        )

add_library(${PROJECT_NAME} ${IOT_HEADERS} ${IOT_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_IOT")
aws_check_headers(${PROJECT_NAME} ${IOT_HEADERS})

aws_add_sanitizers(${PROJECT_NAME})

# We are not ABI stable yet
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 1.0.0)
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 0unstable)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-io)
aws_use_package(aws-c-mqtt)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})
aws_prepare_shared_lib_exports(${PROJECT_NAME})

install(FILES ${AWS_IOT_HEADERS} DESTINATION "include/aws/iot" COMPONENT Development)
#install(FILES ${AWS_MQTT_TESTING_HEADERS} DESTINATION "include/aws/testing/iot" COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)

include(CTest)
if (BUILD_TESTING)
    add_subdirectory(tests)
endif ()
