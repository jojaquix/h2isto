# h2isto
A simple Http request Histogram generator

This project use gtest fot unit testing and libpcap for packet capture.
git installed is required.

## Build
From source dir create a build directory


mkdir build

cd build

cmake ..

cmake --build . --target libgtest

cmake --build . --target libpcap

cmake --build . --target utests

cmake --build . --target h2isto



## How to use
open two consoles and run ./h2isto 10 in one of them  and make curl xxxx in the other one.

## Todo
* a better bpf filter
* hostname from ip
*  
