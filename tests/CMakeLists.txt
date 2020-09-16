include(CTest)
include(AwsTestHarness)
enable_testing()

# set(TEST_SRC metrics_tests.c)
# file(GLOB TESTS ${TEST_SRC})

file(GLOB TEST_HDRS "mqtt_mock_server_handler.h")
set(TEST_SRC metrics_tests.c mqtt_mock_server_handler.c)
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(dummy_test)
add_test_case(devicedefender_task_unsupported_report_format)
add_test_case(devicedefender_task_success)

generate_test_driver(${PROJECT_NAME}-tests)

set(TEST_DD_CLIENT_BINARY_NAME ${PROJECT_NAME}-devicedefender-client)

add_executable(${TEST_DD_CLIENT_BINARY_NAME} "aws_iot_devicedefender_client_test.c")
target_link_libraries(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${PROJECT_NAME})
aws_set_common_properties(${TEST_DD_CLIENT_BINARY_NAME} NO_WEXTRA NO_PEDANTIC)
aws_add_sanitizers(${TEST_DD_CLIENT_BINARY_NAME} ${${PROJECT_NAME}_SANITIZERS})
target_compile_definitions(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_DD_CLIENT_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})