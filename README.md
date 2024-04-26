# Threshold Cryptography using Class Groups 

This library is an Open Source C++ library that implements the Publicly Verifiable Secret Sharing Protocol (PVSS), 1-Round Distributed Key Generation (DKG) Protocol and Resharing protocol from 
[Publicly Verifiable Secret Sharing over Class Groups and Applications to DKG and YOSO](https://eprint.iacr.org/2023/1651).
The library is build on top of the open source [BICYCL](https://gite.lirmm.fr/crypto/bicycl) library, which provides arithmetic
in the ideal class groups of imaginary quadratic fields, alongside a set of cryptographic primitives. 

This library is developed as part of my thesis in Computer Science, and was used for benchmarking purposes.

## Installation
This library relies solely on the BICYCL library and its dependencies for functionality, and optionally on [Google Benchmark](https://github.com/google/benchmark)
for carrying out benchmarks of the protocols mentioned above. In the `./include` folder, a version of the BICYCL library is provided.
Alternatively, one could follow the installation guide from [BICYCL installation guide](https://gite.lirmm.fr/crypto/bicycl/-/blob/master/doc/installation.md?ref_type=heads),
however this might require som rearrangement of the CMakeLists. If using the included BICYCL library, follow the below instuctions:

    apt install g++ libgmp-dev libssl-dev cmake
    mkdir build
    cd build
    cmake ..

To (re-)compile the library, simply run the following command in `./build`:

    make

To execute benchmarks or tests (from `./benchmarks`, `./tests` respectively), run either of the following commands in `./build`:

    make benchs
    make tests

### Windows

For Windows users it is recommended to run a [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) as subsystem, as BICYCL requires some Linux-specific dependencies.

# Structure
In `./src` both `qclpvss.hpp` and `qclpvss.cpp` can be found. This PVSS is the concrete instance from [Publicly Verifiable Secret Sharing over Class Groups and Applications to DKG and YOSO](https://eprint.iacr.org/2023/1651) and is the PVSS used for the 1-Round DKG and Resharing Protocol found in `./src/application/bdkg.cpp` and `./src/application/pvss_reshare.cpp` respectively. In `.src/nizk` all NIZK proofs used throughout the above mentioned protocols can be found. Lastly, in `.src/utils` an implementation of Shamir Secret Sharing can be found, alongside datatypes, utils and lastly `openssl_hash_ext.cpp`, which overrides nescessary implementions of the OpenSSL::HashAlgo::hash template function given in the BICYCL library.

## Multithreading
For benchmarking purposes, a threading pool was utilized to compute multi-exponentiations and products of class group elements. This version can be found in the branch `main`, whereas `non-multithread-PVSS-SNAPSHOT` contains a snapshot of the sequential version.

## Thanks
A big thanks to the authors of [I want to ride my BICYCL: BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/2022/1466)
for providing an extensive library on class groups, which allows for cryptographic protocols on class groups such as those presented
in this library.

## Author
Rasmus Soerensen
