include(CTest)
include(AwsTestHarness)
enable_testing()

file(GLOB TEST_HDRS "mqtt_mock_structs.h")
set(TEST_SRC iotdevice_tests.c metrics_tests.c secure_tunneling_tests.c secure_tunnel_tests.c)
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(library_init)
add_test_case(devicedefender_task_unsupported_report_format)

# Network metrics are only implemented for Linux so far
if (UNIX AND NOT APPLE)
    add_test_case(devicedefender_get_system_network_total)
    add_test_case(devicedefender_get_network_connections)
    add_test_case(devicedefender_success_test)
    add_test_case(devicedefender_custom_metrics_success_test)
    add_test_case(devicedefender_stop_while_running_test)
    add_test_case(devicedefender_publish_failure_callback_invoked)
endif()

add_net_test_case(secure_tunneling_functionality_connect_test)
add_net_test_case(secure_tunneling_functionality_client_token_test)
add_net_test_case(secure_tunneling_fail_and_retry_connection_test)
add_net_test_case(secure_tunneling_store_service_ids_test)
add_net_test_case(secure_tunneling_receive_stream_start_test)
add_net_test_case(secure_tunneling_rejected_service_id_stream_start_test)
add_net_test_case(secure_tunneling_close_stream_on_stream_reset_test)
add_net_test_case(secure_tunneling_session_reset_test)
add_net_test_case(secure_tunneling_serializer_data_message_test)

generate_test_driver(${PROJECT_NAME}-tests)

set(TEST_DD_CLIENT_BINARY_NAME ${PROJECT_NAME}-devicedefender-client)

add_executable(${TEST_DD_CLIENT_BINARY_NAME} "aws_iot_devicedefender_client_test.c")
target_link_libraries(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${PROJECT_NAME})
aws_set_common_properties(${TEST_DD_CLIENT_BINARY_NAME} NO_WEXTRA NO_PEDANTIC)
aws_add_sanitizers(${TEST_DD_CLIENT_BINARY_NAME} ${${PROJECT_NAME}_SANITIZERS})
target_compile_definitions(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

if ($ENV{PROTOBUF_TEST})
    add_subdirectory(tests_protobuf)
endif ()
