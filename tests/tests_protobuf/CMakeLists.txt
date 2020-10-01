set(TEST_PB_BINARY_NAME ${PROJECT_NAME}-st-pb-test)

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_executable(${TEST_PB_BINARY_NAME} "./aws_iot_st_pb_test.cpp" "./Message.pb.cpp" ${PROTO_SRCS} ${PROTO_HDRS})

target_link_libraries(${TEST_PB_BINARY_NAME} PRIVATE ${Protobuf_LIBRARIES} ${PROJECT_NAME})
aws_add_sanitizers(${TEST_PB_BINARY_NAME} ${${PROJECT_NAME}_SANITIZERS})
target_include_directories(${TEST_PB_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})