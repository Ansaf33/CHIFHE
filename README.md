Implementation of Fast Blind Rotation for Bootstrapping FHEs
=====================================

## Fast Blind Rotation for Bootstrapping FHEs
The CHIFHE library contains the implementation of the fully homorphic encryption schemes presented in the paper [Fast Blind Rotation for Bootstrapping FHEs](https://eprint.iacr.org/2023/1564) by using [OpenFHE_v1.1.1](https://github.com/openfheorg/openfhe-development/releases/tag/v1.1.1).

### Requirements
A C++ compiler, the NTL libraries.

## Run the code
1. Configure, build and compile the project. Building OpenFHE for Best Performance
```
mkdir build
cd build
cmake -DWITH_NTL=ON .. 
make 
```
2. Run the `boolean-xzddf` program in `build/bin/examples/binfhe`



3. We recommend using the following CMake command-line configuration for best performance
```
cmake -DWITH_NTL=ON  -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-13 -DCMAKE_CXX_COMPILER=clang++-13 -DWITH_OPENMP=OFF -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread" .. 
```
