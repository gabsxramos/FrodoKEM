# zkpop-go

`zkpop-go` is a Go wrapper around the `libzkpop` library from the
[KEM-NIZKPoP](https://github.com/Chair-for-Security-Engineering/KEM-NIZKPoP)
project. It provides functions to generate keypairs, create Zero-Knowledge
Proofs of Possession (ZKPoP), and verify proofs.

## Getting Started

### Prerequisites

Ensure you have the following installed on your system:
- GCC with AVX2, AES, and BMI2 support.
- OpenSSL development libraries:
  ```bash
  sudo apt install libssl-dev
  ```
- Go programming language (version 1.15+ recommended).
- CMake for building the external library.

### Clone the Repository

First, clone the `zkpop-go` repository:

```bash
git clone --recurse-submodules https://github.com/gabrielzschmitz/zkpop-go.git
cd zkpop-go
```

If you have already cloned the repository without submodules, you can initialize and update them using:

```bash
git submodule update --init --recursive
```

### Build the External Library

The Go wrapper depends on the `libzkpop.a` static library, which needs to be
built from the KEM-NIZKPoP project.

To build the library:

1. Navigate to the project root directory:
   ```bash
   cd zkpop-go
   ```
2. Run the following commands to create the build directory, configure the build, and compile the library:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

This will generate `libzkpop.a` inside `build/lib/`.

### Build the Go Project

Once the library is built, you can compile the Go project and link it to the
required libraries (OpenSSL and `libzkpop.a`):

```bash
CGO_CFLAGS="-mavx2 -maes -mbmi2 -O3 -I/usr/include/openssl" \
CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lssl -lcrypto" \
go build -o zkpop
```

### Run the Test

After building, you can run the main test file (`main.go`) to verify the
implementation:

```bash
./zkpop
```

### Notes
- Ensure you have the appropriate AVX2, AES, and BMI2 support on your system’s
  CPU.
- Modify the OpenSSL paths in `CGO_CFLAGS` and `CGO_LDFLAGS` if your
  installation differs.
- The compilation still not fully complete and need further investigation to
  include all necessary dependencies!

## License

This project is licensed under the MIT License.
