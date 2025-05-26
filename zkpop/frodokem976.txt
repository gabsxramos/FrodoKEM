// FrodoKEM-976 bindings
package zkpop

/*
#include "api_frodo976.h"
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

func KeyPairFrodo976() ([]byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)

	ret := C.crypto_kem_keypair_Frodo976((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))

	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate keypair")
	}
	return pk, sk, nil
}

func EncapsFrodo976(pk []byte) ([]byte, []byte, error) {
	ss := make([]byte, C.CRYPTO_BYTES)
	ct := make([]byte, C.CRYPTO_CIPHERTEXTBYTES)

	ret := C.crypto_kem_enc_Frodo976((*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to encaps")
	}
	return ct, ss, nil
}

func DecapsFrodo976(ct []byte, sk []byte) ([]byte, error) {
	css := make([]byte, C.CRYPTO_BYTES)

	ret := C.crypto_kem_dec_Frodo976((*C.uint8_t)(unsafe.Pointer(&css[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != 0 {
		return nil, fmt.Errorf("failed to perform decapsulation")
	}
	return css, nil
}
