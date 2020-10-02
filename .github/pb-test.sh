#!/bin/sh

# Flag For Building C++
export PROTOBUF_TEST=TRUE
cd ..
mkdir build
cd build
cmake -DBUILD_DEPS=ON ../
make
./tests/tests_protobuf/aws-c-iot-st-pb-test 1
var=$?
./tests/tests_protobuf/aws-c-iot-st-pb-test 2
if [ $? != 0 ]
then
    var=$?
fi
./tests/tests_protobuf/aws-c-iot-st-pb-test 3
if [ $? != 0 ]
then
    var=$?
fi
./tests/tests_protobuf/aws-c-iot-st-pb-test 4
if [ $? != 0 ]
then
    var=$?
fi
./tests/tests_protobuf/aws-c-iot-st-pb-test 5
if [ $? != 0 ]
then
    var=$?
fi
./tests/tests_protobuf/aws-c-iot-st-pb-test 6
if [ $? != 0 ]
then
    var=$?
fi
if [ "$var" != 0 ]
then
    exit 1
fi
exit 0
