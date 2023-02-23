/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "Message.pb.h"
#include <bitset>
#include <string>

extern "C" {
#include <aws/common/assert.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/iotdevice/private/serializer.h>
}

static int execute_tests(
    com::amazonaws::iot::securedtunneling::Message_Type type,
    int32_t streamid,
    int ignorable,
    std::string payload) {
    com::amazonaws::iot::securedtunneling::Message protobufMessage;
    protobufMessage.set_type(type);
    protobufMessage.set_streamid(streamid);
    protobufMessage.set_ignorable(ignorable);
    protobufMessage.set_payload(payload);

    std::string pbBuffer;
    protobufMessage.SerializeToString(&pbBuffer);
    protobufMessage.ParseFromString(pbBuffer);

    struct aws_iot_st_msg c_message;
    c_message.type = (aws_secure_tunnel_message_type)type;
    c_message.stream_id = streamid;
    c_message.ignorable = ignorable;
    c_message.payload = aws_byte_buf_from_c_str(payload.c_str());

    struct aws_allocator *allocator = aws_default_allocator();
    struct aws_byte_buf buffer;
    // SERALIZER //
    aws_iot_st_msg_serialize_from_struct(&buffer, allocator, c_message);
    ///////////////
    // DESERIALIZER //
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&buffer);
    struct aws_iot_st_msg newMes;
    aws_iot_st_msg_deserialize_from_cursor(&newMes, &cursor, allocator);
    ///////////////

    // std::cout << buffer.len << " == " << pbBuffer.length() << std::endl;
    AWS_RETURN_ERROR_IF2(buffer.len == pbBuffer.length(), AWS_OP_ERR);
    for (size_t i = 0; i < buffer.len; i++) {
        // Print buffers side-by-side
        // std::cout << i << " '" << std::bitset<8>(buffer.buffer[i]) << "' '" << std::bitset<8>(pbBuffer[i]) << "'"
        //           << std::endl;
        AWS_RETURN_ERROR_IF2(buffer.buffer[i] == (uint8_t)pbBuffer[i], AWS_OP_ERR);
    }
    return AWS_OP_SUCCESS;
}

/**
 * test_case_one
 * Message with only a payload
 */
static int protobuf_message_test_case_one() {
    com::amazonaws::iot::securedtunneling::Message_Type type =
        com::amazonaws::iot::securedtunneling::Message_Type_UNKNOWN;
    int32_t streamid = 0;
    int ignorable = 0;
    std::string payload = "";
    for (size_t i = 0; i < 10; i++) {
        payload += "xyz !";
    }
    return execute_tests(type, streamid, ignorable, payload);
}

/**
 * test_case_two
 * Message with only an ignorable
 */
int protobuf_message_test_case_two() {
    com::amazonaws::iot::securedtunneling::Message_Type type =
        com::amazonaws::iot::securedtunneling::Message_Type_STREAM_START;
    int32_t streamid = 1;
    int ignorable = 0;
    std::string payload = "";
    return execute_tests(type, streamid, ignorable, payload);
}

/**
 * test_case_three
 * Message with only a streamid
 */
int protobuf_message_test_case_three() {
    com::amazonaws::iot::securedtunneling::Message_Type type =
        com::amazonaws::iot::securedtunneling::Message_Type_UNKNOWN;
    int32_t streamid = 1;
    int ignorable = 0;
    std::string payload = "";

    return execute_tests(type, streamid, ignorable, payload);
}

/**
 * test_case_four
 * Message with only a type
 */
int protobuf_message_test_case_four() {
    com::amazonaws::iot::securedtunneling::Message_Type type =
        com::amazonaws::iot::securedtunneling::Message_Type_STREAM_START;
    int32_t streamid = 0;
    int ignorable = 0;
    std::string payload = "";

    return execute_tests(type, streamid, ignorable, payload);
}

/**
 * test_case_five
 * Message with only all four, small values
 */
int protobuf_message_test_case_five() {
    com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_DATA;
    int32_t streamid = -50000;
    int ignorable = 1;
    std::string payload = "h";

    return execute_tests(type, streamid, ignorable, payload);
}

/**
 * test_case_six
 * Message with only all four, large payload
 */
int protobuf_message_test_case_six() {
    com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_DATA;
    int32_t streamid = 1;
    int ignorable = 1;
    std::string payload = "";
    for (size_t i = 0; i < 10000; i++) {
        payload += "xyz1!";
    }

    return execute_tests(type, streamid, ignorable, payload);
}

static std::vector<int (*)()> test_cases = {
    protobuf_message_test_case_one,
    protobuf_message_test_case_two,
    protobuf_message_test_case_three,
    protobuf_message_test_case_four,
    protobuf_message_test_case_five,
    protobuf_message_test_case_six,
};

int main(int argc, char *argv[]) {
    int i = 0;
    if (argc > 1) {
        i = std::stoi(std::string(argv[1]));
    } else {
        return AWS_OP_ERR;
    }

    if (i < 1 || i > test_cases.size()) {
        std::cout << "protobuf_message_test_case " << i << " NOT_FOUND" << std::endl;
        return AWS_OP_ERR;
    }
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    if (test_cases[i - 1]()) {
        std::cout << "protobuf_message_test_case FAIL" << std::endl;
        return AWS_OP_ERR;
    } else {
        std::cout << "protobuf_message_test_case PASS" << std::endl;
    }
    google::protobuf::ShutdownProtobufLibrary();
    return AWS_OP_SUCCESS;
}
