## AWS C IoT

C99 implementation of AWS IoT cloud services integration with devices

### Currently Included

* aws-c-common: Cross-platform primitives and data structures.
* aws-c-compression: Cross-platform implementation of compression algorithms.
* aws-c-io: Cross-platform event-loops, non-blocking I/O, and TLS implementations.
* aws-c-mqtt: MQTT client.
* aws-c-http: HTTP 1.1 client, and websockets (H2 coming soon).

## Building

The C99 libraries are already included for your convenience as submodules. If you would like to have us build them
by default, be sure to either perform a recursive clone `git clone --recursive` or initialize the submodules via.
`git submodule update --init`. Then, to build, specify the `-DBUILD_DEPS=ON` CMake argument.

If you want to manage these dependencies manually (e.g. you're using them in other projects), simply specify
`-DCMAKE_PREFIX_PATH` to point to the absolute path where you have them installed.

The following commands can be used to build the project with a specific install directory:

```bash
git clone --recursive git@github.com:awslabs/aws-c-iot.git
cmake -DCMAKE_PREFIX_PATH=/opt/crt -DCMAKE_INSTALL_PREFIX=/opt/crt -DBUILD_DEPS=ON -DCMAKE_BUILD_TYPE=Debug -S aws-c-iot -B aws-c-iot/build
cmake --build aws-c-iot/build --target install
```

## Usage

TODO

## License

This library is licensed under the Apache 2.0 License.
