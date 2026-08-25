cmake_minimum_required(VERSION 3.9...3.31)
# In-source builds inherit aws-c-common's module path from the parent. Standalone
# builds must locate the installed modules here: find_package needs an enabled
# language, so it cannot run until after project().
if (NOT IN_SOURCE_BUILD)
    find_file(AWS_GET_VERSION_MODULE AwsGetVersion.cmake
            PATH_SUFFIXES lib/cmake/aws-c-common/modules lib64/cmake/aws-c-common/modules)
    if (NOT AWS_GET_VERSION_MODULE)
        message(FATAL_ERROR "Could not find AwsGetVersion.cmake from an installed aws-c-common. Set CMAKE_PREFIX_PATH to the aws-c-common install prefix.")
    endif()
    get_filename_component(AWS_COMMON_MODULE_DIR "${AWS_GET_VERSION_MODULE}" DIRECTORY)
    list(APPEND CMAKE_MODULE_PATH "${AWS_COMMON_MODULE_DIR}")
endif()

include(AwsGetVersion)
aws_get_version(AWS_C_IOT_VERSION AWS_C_IOT_SOVERSION)

project(aws-c-iot LANGUAGES C VERSION ${AWS_C_IOT_VERSION})
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
include(GNUInstallDirs)

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

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${AWS_C_IOT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${AWS_C_IOT_SOVERSION})

target_compile_definitions(${PROJECT_NAME} PRIVATE -DCJSON_HIDE_SYMBOLS)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-mqtt)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})
aws_prepare_shared_lib_exports(${PROJECT_NAME})

install(FILES ${AWS_IOT_HEADERS}  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/aws/iotdevice" COMPONENT Development)
install(FILES ${AWS_IOT_PRIV_EXPOSED_HEADERS}  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/aws/iotdevice/private" COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/"
        COMPONENT Development)

include(CTest)
if (BUILD_TESTING)
    add_subdirectory(tests)
endif ()
