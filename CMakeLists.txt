cmake_minimum_required(VERSION 3.9)
project(aws-c-iot C)

option(USE_EXTERNAL_DEPS_SOURCES "Use dependencies provided by add_subdirectory command" OFF)

if (USE_EXTERNAL_DEPS_SOURCES)
    set(IN_SOURCE_BUILD ON)

    if (NOT aws-c-common_SOURCE_DIR)
        message(FATAL_ERROR "USE_EXTERNAL_DEPS_SOURCES option is set, but aws-c-common project is not configured."
            " aws-c-common must be added using add_subdirectory command (or one of the higher-level commands that"
            " uses add_subdirectory, like FetchContent)")
    endif()

    list(APPEND CMAKE_MODULE_PATH "${aws-c-common_SOURCE_DIR}/cmake")
endif()

if (NOT IN_SOURCE_BUILD)
    # this is required so we can use aws-c-common's CMake modules
    find_package(aws-c-common REQUIRED)
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
    file(GLOB AWS_IOT_OS_SRC
        "source/linux/*.c"
        )
endif()

file(GLOB AWS_IOT_HEADERS
        "include/aws/iotdevice/*.h"
        )

file(GLOB AWS_IOT_PRIV_HEADERS
        "include/aws/iotdevice/private/*.h"
        )

file(GLOB AWS_IOT_PRIV_EXPOSED_HEADERS
        "include/aws/iotdevice/private/serializer.h"
        "include/aws/iotdevice/private/secure_tunneling_impl.h"
        )

file(GLOB AWS_IOT_SRC
        "source/*.c"
        )

file(GLOB IOT_HEADERS
        ${AWS_IOT_HEADERS}
        ${AWS_IOT_PRIV_HEADERS}
        )

file(GLOB IOT_SRC
        ${AWS_IOT_SRC}
        ${AWS_IOT_OS_SRC}
        ${AWS_IOT_PRIV_HEADERS}
        )

add_library(${PROJECT_NAME} ${IOT_HEADERS} ${IOT_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_IOTDEVICE")
aws_check_headers(${PROJECT_NAME} ${AWS_IOT_HEADERS})

aws_add_sanitizers(${PROJECT_NAME})

# We are not ABI stable yet
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 1.0.0)
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 0unstable)

target_compile_definitions(${PROJECT_NAME} PRIVATE -DCJSON_HIDE_SYMBOLS)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-mqtt)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})
aws_prepare_shared_lib_exports(${PROJECT_NAME})

install(FILES ${AWS_IOT_HEADERS}  DESTINATION "${INCLUDE_DIRECTORY}/aws/iotdevice" COMPONENT Development)
install(FILES ${AWS_IOT_PRIV_EXPOSED_HEADERS}  DESTINATION "${INCLUDE_DIRECTORY}/aws/iotdevice/private" COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${LIBRARY_DIRECTORY}/cmake/${PROJECT_NAME}/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/cmake/${PROJECT_NAME}/"
        COMPONENT Development)

include(CTest)
if (BUILD_TESTING)
    add_subdirectory(tests)
endif ()
