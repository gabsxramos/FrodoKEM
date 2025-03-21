// main.go

package main

/*
#cgo CFLAGS: -I/home/<SEULOCAL>/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640/ -I/usr/include/
#cgo LDFLAGS: -L/home/<SEULOCAL/projetos/Grupo_PQC/edital12PIBIC/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640/ -L/usr/lib/ -lfrodo -lssl -lcrypto 
*/
import "C"

import (
	"fmt"
	"log"
	"zkpop-go/zkpop" // Make sure to import the package correctly
)

func main() {
	// Test KeyPair generation
	fmt.Println("Generating keypair with zkpop...")

//	pk, sk, zkpopProof, err := zkpop.KeyPair()
	pk, sk, zkpopProof, err := zkpop.KeyPair()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	fmt.Printf("Public Key: %x\n", pk)
	fmt.Printf("Secret Key: %x\n", sk)
	fmt.Printf("Zero-Knowledge Proof: %x\n", zkpopProof)

	// Test zkpop verification
	//fmt.Println("Verifying zkpop...")

	/*isValid := zkpop.VerifyZKPop(pk, zkpopProof) // Call zkpop.VerifyZKPop correctly
	if isValid {
		fmt.Println("zkpop verification successful!")
	} else {
		fmt.Println("zkpop verification failed.")
	}*/
}

