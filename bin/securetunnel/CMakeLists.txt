project(securetunnel C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

file(GLOB SECURETUNNEL_SRC
        "*.c"
        )

set(SECURETUNNEL_PROJECT_NAME securetunnel)
add_executable(${SECURETUNNEL_PROJECT_NAME} ${SECURETUNNEL_SRC})
aws_set_common_properties(${SECURETUNNEL_PROJECT_NAME})


target_include_directories(${SECURETUNNEL_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${SECURETUNNEL_PROJECT_NAME} aws-c-iot)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " securetunnel will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${SECURETUNNEL_PROJECT_NAME}
        EXPORT ${SECURETUNNEL_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
