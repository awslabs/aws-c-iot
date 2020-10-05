#!/bin/bash
# Flag For Building C++ pbuf binary
export PROTOBUF_TEST=TRUE
cd ..
mkdir build
cd build
cmake -DBUILD_DEPS=ON ../
make
var=0
for i in {1..6}
do
  ./tests/tests_protobuf/aws-c-iot-st-pb-test $i
  if [ $? != 0 ]
  then
    var=$?
  fi
done
if [ "$var" != 0 ]
then
    exit 1
fi
exit 0
