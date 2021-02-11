include(CTest)
include(AwsTestHarness)
enable_testing()

file(GLOB TEST_HDRS "mqtt_mock_structs.h")
set(EXTERNAL_SRC "external/cJSON.c")
set(TEST_SRC metrics_tests.c secure_tunneling_tests.c)
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC} ${EXTERNAL_SRC})

add_test_case(devicedefender_task_unsupported_report_format)

# Network metrics are only implemented for Linux so far
if (UNIX AND NOT APPLE)
    add_test_case(devicedefender_get_system_network_total)
    add_test_case(devicedefender_get_network_connections)
    # add_test_case(devicedefender_success_test) TODO: Re-enable this
    add_test_case(secure_tunneling_handle_stream_start_test)
    add_test_case(secure_tunneling_handle_data_receive_test)
    add_test_case(secure_tunneling_handle_stream_reset_test)
    add_test_case(secure_tunneling_handle_session_reset_test)
    add_test_case(secure_tunneling_init_websocket_options_test)
    add_test_case(secure_tunneling_handle_send_data)
    add_test_case(secure_tunneling_handle_send_data_stream_start)
    add_test_case(secure_tunneling_handle_send_data_stream_reset)
endif()

generate_test_driver(${PROJECT_NAME}-tests)

set(TEST_DD_CLIENT_BINARY_NAME ${PROJECT_NAME}-devicedefender-client)

add_executable(${TEST_DD_CLIENT_BINARY_NAME} "aws_iot_devicedefender_client_test.c")
target_link_libraries(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${PROJECT_NAME})
aws_set_common_properties(${TEST_DD_CLIENT_BINARY_NAME} NO_WEXTRA NO_PEDANTIC)
aws_add_sanitizers(${TEST_DD_CLIENT_BINARY_NAME} ${${PROJECT_NAME}_SANITIZERS})
target_compile_definitions(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

# Secure Tunneling test client
set(TEST_ST_CLIENT_BINARY_NAME ${PROJECT_NAME}-secure_tunneling-client)
add_executable(${TEST_ST_CLIENT_BINARY_NAME} "aws_iot_secure_tunneling_client_test.c")
target_link_libraries(${TEST_ST_CLIENT_BINARY_NAME} PRIVATE ${PROJECT_NAME})
aws_set_common_properties(${TEST_ST_CLIENT_BINARY_NAME} NO_WEXTRA NO_PEDANTIC)
aws_add_sanitizers(${TEST_ST_CLIENT_BINARY_NAME} ${${PROJECT_NAME}_SANITIZERS})
target_compile_definitions(${TEST_ST_CLIENT_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_ST_CLIENT_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

if ($ENV{PROTOBUF_TEST})
    add_subdirectory(tests_protobuf)
endif ()
