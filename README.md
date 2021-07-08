# h2isto
A simple Http request Histogram generator


This project use gtest fot unit testing and libpcap for packet capture.
**git**  and **github access**.
 
**CMAKE** is used as generation tool and a C++11 compiler in any
**linux** distribution should work fine for building.


## Build
From source dir create a build directory, and download and 

````
mkdir build
cd build
cmake ..

````

To download and build all dependencies use
```
cmake --build . --target deps
```

Dependencies could be download and build independently

```
cmake --build . --target libpcap
```
```
cmake --build . --target libgtest
```
```
cmake --build . --target libglog
```


To build unit test project

```
cmake --build . --target utests
```

To build de binary
```
cmake --build . --target h2isto
```


## How to use
open two consoles and run ./h2isto --secs 10 as admin in one of them and make a curl xxxx in the other one.

check ./h2isto --help for other options

## Todo
* a better bpf filter to detect other http requests
* a better flags validation
* hostname from ip
* https support
* much more ...




