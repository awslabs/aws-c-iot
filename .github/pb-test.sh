#!/bin/sh
export PROTOBUF_TEST=TRUE
cd .. 
mkdir build
cd build
cmake -DBUILD_DEPS=ON ../
make
./tests/protobuf-test/aws-c-iot-st-pb-test 5 || exit 1

exit 0