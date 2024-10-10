// zkpop/zkpop.go
package zkpop

/*
#cgo CFLAGS: -I../external/KEM-NIZKPoP/kyber-zkpop/avx2
#cgo LDFLAGS: -L../build/lib -lzkpop -static
#include "zkpop.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// KeyPair generates a keypair and proof of knowledge (zkpop).
func KeyPair() ([]byte, []byte, []byte, error) {
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
