# zkpop-go

`zkpop-go` is a Go wrapper around the 
[KEM-NIZKPoP](https://github.com/Chair-for-Security-Engineering/KEM-NIZKPoP)
project. It provides functions to generate keypairs, create Zero-Knowledge
Proofs of Possession (ZKPoP), and verify proofs.

## Getting Started

### Supported algorithms

Currently, our binding supports functions like Keygen, Keygen-zkpop, Encaps, Decaps, and Verify-zkpop for FrodoKEM-640.

### Prerequisites

Ensure you have the following installed on your system:
- GCC with AVX2, AES, and BMI2 support.
- OpenSSL development libraries:
  ```bash
  sudo apt install libssl-dev
  ```
- Go programming language (version 1.15+ recommended).

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

1. Frodo-KEM
To build the library, navigate to `external/KEM-NIZKPoP/frodo-zkpop`:

`make clean && make OPT_LEVEL=FAST USE_OPENSSL=FALSE GENERATION_A=SHAKE128 ZKPOP_N=65536 ZKPOP_TAU=8 && frodo640/test_KEM`

If you are going to use openssl, just do a `make` instead.

It's important to rename the files with the default name lib<name>.a.
If you have multiple versions named libfrodo.a in different folders, 
the Go/C linker in main.go may get confused or pick the wrong one — especially if a -L ends up pointing to the wrong directory or multiple ones are used.
`cd external/KEM-NIZKPoP/frodo-zkpop`
`mv frodo640/libfrodo.a frodo640/libfrodo640.a`
`mv frodo976/libfrodo.a frodo976/libfrodo976.a`
`mv frodo1344/libfrodo.a frodo1344/libfrodo1344.a`


### Build the Go Project

Before building the project, you need to change `main.go` because (sadly!) `CFLAGS` and `LDFLAGS` contains absolute paths. Change it to your path.

Now you can build the project (navigate to `zkpop-go/` directory):

```bash
go clean
go build -o zkpop-exec`
```

### Execution

```bash
./zkpop
```

## License

This project is licensed under the MIT License.



