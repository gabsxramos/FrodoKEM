// zkpop/zkpop.go — Frodo1344 NIZKPoP
package zkpop

/*
#cgo CFLAGS: -I../external/KEM-NIZKPoP/frodo-zkpop/src
#cgo LDFLAGS: -L../external/KEM-NIZKPoP/frodo-zkpop/frodo1344 -lfrodo

#include "api_frodo1344.h"
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func KeyPairFrodo1344NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)
	var zkpop *C.uint8_t
	var zkpopSize C.size_t

	ret := C.crypto_kem_keypair_nizkpop_Frodo1344((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop, &zkpopSize)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate keypair")
	}

	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop), C.int(zkpopSize))
	C.free(unsafe.Pointer(zkpop))

	return pk, sk, zkpopGo, nil
}

func VerifyFrodo1344ZKPop(pk []byte, zkpop []byte) bool {
	ret := C.crypto_nizkpop_verify_Frodo1344((*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)))
	return ret == 0
}
