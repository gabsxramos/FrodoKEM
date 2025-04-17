// zkpop/zkpop_frodo976.go
package zkpop

/*
#cgo CFLAGS: -I/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/src
#cgo LDFLAGS: -L/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo976 -lfrodo976
#include "api_frodo976.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Frodo976Impl struct{}

func (f Frodo976Impl) KeyPair() ([]byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)
	ret := C.crypto_kem_keypair_Frodo976(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("Frodo976 keypair generation failed")
	}
	return pk, sk, nil
}

func (f Frodo976Impl) Encaps(pk []byte) ([]byte, []byte, error) {
	ct := make([]byte, C.CRYPTO_CIPHERTEXTBYTES)
	ss := make([]byte, C.CRYPTO_BYTES)
	ret := C.crypto_kem_enc_Frodo976(
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		(*C.uchar)(unsafe.Pointer(&pk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("Frodo976 encapsulation failed")
	}
	return ct, ss, nil
}

func (f Frodo976Impl) Decaps(ct, sk []byte) ([]byte, error) {
	ss := make([]byte, C.CRYPTO_BYTES)
	ret := C.crypto_kem_dec_Frodo976(
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("Frodo976 decapsulation failed")
	}
	return ss, nil
}

func (f Frodo976Impl) KeyPairNIZK() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)
	var zkpop *C.uchar
	var zkpopSize C.ulong

	ret := C.crypto_kem_keypair_nizkpop_Frodo976(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
		&zkpop,
		&zkpopSize,
	)
	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("Frodo976 keypair NIZK failed")
	}
	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop), C.int(zkpopSize))
	C.free(unsafe.Pointer(zkpop))
	return pk, sk, zkpopGo, nil
}

func (f Frodo976Impl) VerifyZKPop(pk, zkpop []byte) bool {
	ret := C.crypto_nizkpop_verify_Frodo976(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}