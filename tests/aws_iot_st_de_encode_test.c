#include <aws/common/byte_buf.h>
#include <aws/iotdevice/private/serializer.h>
#include <stdio.h>

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

int main(int argc, char *argv[]) {
  struct aws_iot_st_msg mes;
  mes.streamId = 1;
  mes.type = DATA;
  mes.ignorable = 1;
  mes.payload = aws_byte_buf_from_c_str("h");
  printf("Payload: %s.\n", (char*)(mes.payload.buffer));
  printf("StreamId: %d.\n", (int)mes.streamId);
  printf("Ignorable: %d.\n", mes.ignorable);
  printf("Type: %d.\n\n", mes.type);

  struct aws_allocator *allocator = aws_default_allocator();
  struct aws_byte_buf buffer;
  // SERALIZER //
  aws_iot_st_msg_serialize_from_struct(&buffer, allocator, mes);
  ///////////////

  printf("%zu\n", buffer.len);
    for (int i = 0; i < buffer.len; i++) {    
         printf("Byte #%d: "BYTE_TO_BINARY_PATTERN "\n", i+1, BYTE_TO_BINARY(buffer.buffer[i]));
    }
  
  ////////////////////////////////////////////
  // FILE * pFile;
  // pFile = fopen ("./data.bin", "wb");
  // fwrite(buffer, sizeof(char), strlen(buffer), pFile);
  // fclose(pFile); 
  ////////////////////////////////////////////

  // DESERIALIZER //    
  struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&buffer);
  struct aws_iot_st_msg newMes;
  aws_iot_st_msg_deserialize_from_cursor(&newMes, &cursor, allocator);
  //////////////////

  printf("Payload: %s.\n", (char*)(newMes.payload.buffer));
  printf("StreamId: %d.\n", (int)newMes.streamId);
  printf("Ignorable: %d.\n", newMes.ignorable);
  printf("Type: %d.\n", newMes.type);
  return 0;
}
