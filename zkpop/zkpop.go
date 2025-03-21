// zkpop/zkpop.go
package zkpop

/*
#include "api_frodo640.h"
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h> //from OpenSSL 1.1.1
#include <openssl/aes.h>
*/
import "C"

import (
        "fmt"
        "unsafe"
)


//Frodo part
func KeyPair() ([]byte, []byte, []byte, error) {
        fmt.Println(C.CRYPTO_ALGNAME)
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




// KeyPair generates a keypair and proof of knowledge (zkpop).
/*func KeyPair() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.KYBER_INDCPA_PUBLICKEYBYTES)
	sk := make([]byte, C.KYBER_INDCPA_SECRETKEYBYTES)
	var zkpop *C.uint8_t
	var zkpopSize C.size_t

	ret := C.crypto_kem_keypair_nizkpop((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop, &zkpopSize)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate keypair")
	}

	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop), C.int(zkpopSize))
	C.free(unsafe.Pointer(zkpop)) // Free zkpop allocated in C

	return pk, sk, zkpopGo, nil
}

// VerifyZKPop verifies the proof of knowledge.
func VerifyZKPop(pk []byte, zkpop []byte) bool {
	ret := C.crypto_nizkpop_verify((*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)))
	return ret == 0
}
*/
