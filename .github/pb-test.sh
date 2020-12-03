#!/bin/bash
# Flag For Building C++ pbuf binary
export PROTOBUF_TEST=TRUE
cd ..
mkdir build
cd build
cmake ../
make
failed=0
set -e
for i in {1..6}
do
  ./tests/tests_protobuf/aws-c-iot-st-pb-test $i
  if [ $? != 0 ]
  then
    failed=$?
  fi
done
if [ "$failed" != 0 ]
then
    exit 1
fi
exit 0
