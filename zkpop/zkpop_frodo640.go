// zkpop/zkpop_frodo640.go
package zkpop

/*
#cgo CFLAGS: -I/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/src
#cgo LDFLAGS: -L/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640 -lfrodo640
#include "api_frodo640.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type Frodo640Impl struct{}

func (f Frodo640Impl) KeyPair() ([]byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)

	ret := C.crypto_kem_keypair_Frodo640(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("Frodo640 KeyPair failed")
	}
	return pk, sk, nil
}

func (f Frodo640Impl) Encaps(pk []byte) ([]byte, []byte, error) {
	ct := make([]byte, C.CRYPTO_CIPHERTEXTBYTES)
	ss := make([]byte, C.CRYPTO_BYTES)

	ret := C.crypto_kem_enc_Frodo640(
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		(*C.uchar)(unsafe.Pointer(&pk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("Frodo640 Encaps failed")
	}
	return ct, ss, nil
}

func (f Frodo640Impl) Decaps(ct, sk []byte) ([]byte, error) {
	ss := make([]byte, C.CRYPTO_BYTES)

	ret := C.crypto_kem_dec_Frodo640(
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("Frodo640 Decaps failed")
	}
	return ss, nil
}

func (f Frodo640Impl) KeyPairNIZK() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)

	var zkpop *C.uchar
	var zkpopSize C.ulong

	ret := C.crypto_kem_keypair_nizkpop_Frodo640(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
		&zkpop, &zkpopSize,
	)
	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("Frodo640 KeyPairNIZK failed")
	}
	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop), C.int(zkpopSize))
	C.free(unsafe.Pointer(zkpop))
	return pk, sk, zkpopGo, nil
}

func (f Frodo640Impl) VerifyZKPop(pk, zkpop []byte) bool {
	ret := C.crypto_nizkpop_verify_Frodo640(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}
