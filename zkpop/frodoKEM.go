// FrodoKEM original bindings, just for comparison purposes
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

//binding for crypto_kem_keypair_Frodo640
func KeyPairFrodo640()([]byte, []byte, error){
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
        sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)

	ret := C.crypto_kem_keypair_Frodo640((*C.uint8_t)(unsafe.Pointer(&pk[0])),
                (*C.uint8_t)(unsafe.Pointer(&sk[0])))

	if ret != 0 {
                return nil, nil, fmt.Errorf("failed to generate keypair")
        }
	return pk, sk, nil
}

//Encapsulation for a given public key pk
//Returns a ciphertext ct and a 16-byte shared secret ss
func EncapsFrodo640(pk []byte)([]byte, []byte, error){
//	crypto_kem_enc_Frodo640
//	(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
	ss := make([]byte, C.CRYPTO_BYTES)
	ct := make([]byte, C.CRYPTO_CIPHERTEXTBYTES)

	ret := C.crypto_kem_enc_Frodo640((*C.uint8_t)(unsafe.Pointer(&ct[0])),
					   (*C.uint8_t)(unsafe.Pointer(&ss[0])),
					   (*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != 0 {
                return nil, nil, fmt.Errorf("failed to encaps")
        }
        return ct, ss, nil
}

//Given a ciphertext ct and a private key sk
//returns a candidate shared secret css
func DecapsFrodo640(ct []byte, sk []byte)([]byte, error){
	//crypto_kem_dec_Frodo640
	css := make([]byte, C.CRYPTO_BYTES)

        ret := C.crypto_kem_dec_Frodo640((*C.uint8_t)(unsafe.Pointer(&css[0])),
                                           (*C.uint8_t)(unsafe.Pointer(&ct[0])),
                                           (*C.uint8_t)(unsafe.Pointer(&sk[0])))
        if ret != 0 {
                return nil, fmt.Errorf("failed to perform decapsulation")
        }
        return css, nil
}
