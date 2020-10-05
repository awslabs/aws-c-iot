FROM ubuntu:18.04

run apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y git cmake autoconf libtool g++ && \
    apt-get install -y libssl-dev build-essential openssl
run git clone --recursive https://github.com/protocolbuffers/protobuf.git --branch 3.6.x && \
    cd protobuf && ./autogen.sh && ./autogen.sh && ./configure && make && make check
run cd protobuf && make install && ldconfig
WORKDIR /home

ADD entry_script.sh /home/protobuf_test
RUN chmod a+x /home/protobuf_test
ENTRYPOINT ["/home/protobuf_test"]
