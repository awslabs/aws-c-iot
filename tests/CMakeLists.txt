include(CTest)
include(AwsTestHarness)
include(AwsLibFuzzer)
enable_testing()

set(TEST_SRC metrics_tests.c)
file(GLOB TESTS ${TEST_SRC})

add_test_case(dummy_test)

generate_test_driver(${PROJECT_NAME}-tests)
