# zkpop-go

`zkpop-go` is a Go wrapper around the 
[KEM-NIZKPoP](https://github.com/Chair-for-Security-Engineering/KEM-NIZKPoP)
project. It provides functions to generate keypairs, create Zero-Knowledge
Proofs of Possession (ZKPoP), and verify proofs.

## Credits

This project was originally based on [zkpop-go](https://github.com/gabrielzschmitz/zkpop-go) developed by [Gabriel Zschmitz](https://github.com/gabrielzschmitz).

Several modifications and adaptations were made to focus on implementing FrodoKEM in the 640, 976 and 1344 variants.

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
git clone --recurse-submodules https://github.com/gabsxramos/FrodoKEM
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

### Build the Go Project

Before building the project, you need to change `main.go` because (sadly!) `CFLAGS` and `LDFLAGS` contains absolute paths. Change it to your path.

Now you can build the project (navigate to `zkpop` directory):

```bash
go clean
go build -o zkpop-exec`
```

### Execution

```bash
./zkpop
```
Each .txt has a version of frodoKEM in relation to its respective code. For example, main640.txt contains the code main.go with the version of frodo 640 and so on. This is repeated with frodoKEM.go, zkpop.go and api_frodo as well. So before running the code, choose which version of FrodoKEM you want and copy and paste the .txt of it into your respective .go file.

## License

This project is licensed under the MIT License.