// zkpop/zkpop.go
package zkpop

/*
#cgo CFLAGS: -I/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpopGabriel/external/KEM-NIZKPoP/frodo-zkpop/src
#cgo LDFLAGS: /mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpopGabriel/external/KEM-NIZKPoP/frodo-zkpop/frodo640/libfrodo.a
#include "api_frodo640.h"
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
*/
import "C"

import "C"

import (
        "fmt"
        "unsafe"
)


//Frodo640-Keypair with NIZKPoP
func KeyPairFrodo640NIZKPoP() ([]byte, []byte, []byte, error) {
        //fmt.Println(C.CRYPTO_ALGNAME)
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
        sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)
        var zkpop *C.uint8_t
        var zkpopSize C.size_t

        ret := C.crypto_kem_keypair_nizkpop_Frodo640((*C.uint8_t)(unsafe.Pointer(&pk[0])),
                (*C.uint8_t)(unsafe.Pointer(&sk[0])),
                &zkpop, &zkpopSize)

        if ret != 0 {
                return nil, nil, nil, fmt.Errorf("failed to generate keypair")
        }

        zkpopGo := C.GoBytes(unsafe.Pointer(zkpop), C.int(zkpopSize))
        C.free(unsafe.Pointer(zkpop)) // Free zkpop allocated in C

        return pk, sk, zkpopGo, nil
}

func VerifyFrodo640ZKPop(pk []byte, zkpop []byte) bool {
        ret := C.crypto_nizkpop_verify_Frodo640((*C.uchar)(unsafe.Pointer(&pk[0])),
                (*C.uchar)(unsafe.Pointer(&zkpop[0])),
                C.ulong(len(zkpop))) //we could set a 'CRYPTO_NIZKPOPBYTES' in the .h API file...
        return ret == 0
}





