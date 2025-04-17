// zkpop/zkpop.go
package zkpop

import (
	"errors"
)

// Define FrodoKEM parameter sets
const (
	Frodo640 = "Frodo640"
	//Frodo976 = "Frodo976"
	//Frodo1344 = "Frodo1344"
)

// Unified interface for KEM operations
type FrodoKEM interface {
	KeyPair() (pk, sk []byte, err error)
	Encaps(pk []byte) (ct, ss []byte, err error)
	Decaps(ct, sk []byte) (ss []byte, err error)
	KeyPairNIZK() (pk, sk, zkpop []byte, err error)
	VerifyZKPop(pk, zkpop []byte) bool
}

func GetFrodoKEM(version string) (FrodoKEM, error) {
	switch version {
	case Frodo640:
		return Frodo640Impl{}, nil
	// case Frodo976:
	// 	return Frodo976Impl{}, nil
	// case Frodo1344: 
	// 	return Frodo1344Impl{}, nil
	default:
		return nil, errors.New("unsupported FrodoKEM version")
	}
}

