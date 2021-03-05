## AWS C IoT

C99 implementation of AWS IoT cloud services integration with devices

## License

This library is licensed under the Apache 2.0 License.

## Usage

### Building

#### Building s2n-tls (Linux Only)

If you are building on Linux, you will need to build aws-lc and s2n-tls first.

```
git clone git@github.com:awslabs/aws-lc.git
cmake -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-lc -B aws-lc/build
cmake --build aws-lc/build --target install --parallel

git clone git@github.com:aws/s2n-tls.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S s2n-tls -B s2n-tls/build
cmake --build s2n-tls/build --target install --parallel
```

#### Building aws-c-iot and Remaining Dependencies

Note that aws-c-iot has several dependencies that need to be built.

```
git clone git@github.com:awslabs/aws-c-common.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-common -B aws-c-common/build
cmake --build aws-c-common/build --target install --parallel

git clone git@github.com:awslabs/aws-c-cal.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-cal -B aws-c-cal/build
cmake --build aws-c-cal/build --target install --parallel

git clone git@github.com:awslabs/aws-c-io.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-io -B aws-c-io/build
cmake --build aws-c-io/build --target install --parallel

git clone git@github.com:awslabs/aws-c-compression.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-compression -B aws-c-compression/build
cmake --build aws-c-compression/build --target install --parallel

git clone git@github.com:awslabs/aws-c-http.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-http -B aws-c-http/build
cmake --build aws-c-http/build --target install --parallel

git clone git@github.com:awslabs/aws-c-mqtt.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-mqtt -B aws-c-mqtt/build
cmake --build aws-c-mqtt/build --target install --parallel

git clone git@github.com:awslabs/aws-c-iot.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-iot -B aws-c-iot/build
cmake --build aws-c-iot/build --target install --parallel
```
