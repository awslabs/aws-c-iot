#include <string>
#include <bitset>
#include "Message.pb.h"

extern "C" {
  #include <aws/common/assert.h>
  #include <aws/common/byte_buf.h>
  #include <aws/common/error.h>
  #include <aws/iotdevice/private/serializer.h>
}

static int execTest(com::amazonaws::iot::securedtunneling::Message_Type type, int32_t streamid, int ignorable, std::string payload) {
  com::amazonaws::iot::securedtunneling::Message protobufMessage;
  protobufMessage.set_type(type);
  protobufMessage.set_streamid(streamid);
  protobufMessage.set_ignorable(ignorable);
  protobufMessage.set_payload(payload);

  std::string pbBuffer;
  protobufMessage.SerializeToString(&pbBuffer);
  protobufMessage.ParseFromString(pbBuffer);

  struct aws_iot_st_msg c_message;
  c_message.type = (aws_iot_st_message_type)type;
  c_message.streamId = streamid;
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
  
  if (buffer.len != pbBuffer.length()) {
    // std::cout << buffer.len << " == " << pbBuffer.length() << std::endl;
    return AWS_OP_ERR;
  }
  for (size_t i = 0; i < buffer.len; i++) {
    if (buffer.buffer[i] != (uint8_t)pbBuffer[i]) {
      // Print buffers side-by-side
      // std::cout << i << " '" << std::bitset<8>(buffer.buffer[i]) << "' '"<< std::bitset<8>(pbBuffer[i]) <<"'"<< std::endl;
      return AWS_OP_ERR;
    }
  }
  return AWS_OP_SUCCESS;
}


/**
 * test_case_one
 * Message with only a payload
 */
static int protobuf_message_test_case_one() {
  com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_UNKNOWN;
  int32_t streamid = 0;
  int ignorable = 0;
  std::string payload = "";
  for (size_t i = 0; i < 10; i++)
  {
    payload += "xyz !";
  }
  return execTest(type, streamid, ignorable, payload);
}

/**
 * test_case_two
 * Message with only an ignorable
 */
int protobuf_message_test_case_two() {
  com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_UNKNOWN;
  int32_t streamid = 0;
  int ignorable = 1;
  std::string payload = "";
  return execTest(type, streamid, ignorable, payload);
}

/**
 * test_case_three
 * Message with only a streamid
 */
int protobuf_message_test_case_three() {
  com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_UNKNOWN;
  int32_t streamid = 1;
  int ignorable = 0;
  std::string payload = "";

  return execTest(type, streamid, ignorable, payload);
}

/**
 * test_case_four
 * Message with only a type
 */
int protobuf_message_test_case_four() {
  com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_STREAM_START;
  int32_t streamid = 0;
  int ignorable = 0;
  std::string payload = "";

  return execTest(type, streamid, ignorable, payload);
}

/**
 * test_case_five
 * Message with only all four, small values
 */
int protobuf_message_test_case_five() {
  com::amazonaws::iot::securedtunneling::Message_Type type = com::amazonaws::iot::securedtunneling::Message_Type_DATA;
  int32_t streamid = 1;
  int ignorable = 1;
  std::string payload = "h";
  
  return execTest(type, streamid, ignorable, payload);
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
  for (size_t i = 0; i < 10000; i++)
  {
    payload += "xyz1!";
  }

  return execTest(type, streamid, ignorable, payload);
}

int main(int argc, char *argv[]) {
  char i = 0;
  if (argc > 1) {
    i = *argv[1];
  }
  else {
    return AWS_OP_ERR;
  }
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  switch (i) {
    case '1':
      if (protobuf_message_test_case_one()) { 
        return AWS_OP_ERR;
      }
      break;
    case '2': 
      if (protobuf_message_test_case_two()) { 
        return AWS_OP_ERR;
      }
      break;
    case '3':
      if (protobuf_message_test_case_three()) {
        return AWS_OP_ERR;
      }
      break;
    case '4':
      if (protobuf_message_test_case_four()) { 
        return AWS_OP_ERR;
      }
      break;
    case '5':
      if (protobuf_message_test_case_five()) {
        return AWS_OP_ERR;
        }
        break;
    case '6':
      if (protobuf_message_test_case_six()) { 
        return AWS_OP_ERR;
      }
      break;
    default:
      return AWS_OP_ERR;
  }
  google::protobuf::ShutdownProtobufLibrary();
  return AWS_OP_SUCCESS;
}