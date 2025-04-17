// main.go
package main

/*
#cgo CFLAGS: -I/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/src \
             -I/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/tests
#cgo LDFLAGS: -L/mnt/c/Users/Gabriela\ Ramos/OneDrive/Desktop/Codes/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640 -lfrodo640
*/

import "C"

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"time"
	"zkpop-go/zkpop"
)

func measureOpTime(op func() error, N int) (mean, stddev float64) {
	times := make([]float64, N)
	var sum float64

	for i := 0; i < N; i++ {
		start := time.Now()
		err := op()
		if err != nil {
			log.Fatalf("operation failed: %v", err)
		}
		dur := float64(time.Since(start).Microseconds())
		times[i] = dur
		sum += dur
	}

	mean = sum / float64(N)

	for _, t := range times {
		stddev += (t - mean) * (t - mean)
	}
	stddev = math.Sqrt(stddev / float64(N))

	return
}

func testFrodoKEM(version string, N int) {
	fmt.Printf("Testing %s...\n", version)
	kem, err := zkpop.GetFrodoKEM(version)
	if err != nil {
		log.Fatalf("%v", err)
	}

	pk, sk, err := kem.KeyPair()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}

	meanKeygen, stdKeygen := measureOpTime(func() error {
		pk, sk, err = kem.KeyPair()
		return err
	}, N)

	ct, ss, err := kem.Encaps(pk)
	if err != nil {
		log.Fatalf("Encaps failed: %v", err)
	}

	meanEnc, stdEnc := measureOpTime(func() error {
		ct, ss, err = kem.Encaps(pk)
		return err
	}, N)

	_, err = kem.Decaps(ct, sk)
	if err != nil {
		log.Fatalf("Decaps warmup failed: %v", err)
	}

	meanDec, stdDec := measureOpTime(func() error {
		dec, err := kem.Decaps(ct, sk)
		if err != nil {
			return err
		}
		if !bytes.Equal(dec, ss) {
			return fmt.Errorf("decapsulation mismatch")
		}
		return nil
	}, N)

	fmt.Println("================================================================")
	fmt.Println("Tests PASSED. All session keys matched.")
	fmt.Println("Operation         Iterations  Time(us): mean  stddev")
	fmt.Printf("Key generation     %9d  %12.3f %7.3f\n", N, meanKeygen, stdKeygen)
	fmt.Printf("KEM encapsulate    %9d  %12.3f %7.3f\n", N, meanEnc, stdEnc)
	fmt.Printf("KEM decapsulate    %9d  %12.3f %7.3f\n", N, meanDec, stdDec)
	fmt.Println("================================================================")
}

func testFrodoNIZK(version string, N int) {
	fmt.Printf("Testing %s-NIZKPoP...\n", version)
	kem, err := zkpop.GetFrodoKEM(version)
	if err != nil {
		log.Fatalf("%v", err)
	}

	pk, _, zk, err := kem.KeyPairNIZK()
	if err != nil {
		log.Fatalf("KeyPairNIZK failed: %v", err)
	}

	meanNizk, stdNizk := measureOpTime(func() error {
		pk, _, zk, err = kem.KeyPairNIZK()
		return err
	}, N)

	valid := kem.VerifyZKPop(pk, zk)
	if !valid {
		log.Fatal("ZKPoP verification failed")
	}

	meanVerif, stdVerif := measureOpTime(func() error {
		if !kem.VerifyZKPop(pk, zk) {
			return fmt.Errorf("verification failed")
		}
		return nil
	}, N)

	fmt.Println("================================================================")
	fmt.Println("Tests PASSED. All session keys matched.")
	fmt.Println("Operation         Iterations  Time(us): mean  stddev")
	fmt.Printf("Keygen NIZKPoP     %9d  %12.3f %7.3f\n", N, meanNizk, stdNizk)
	fmt.Printf("Verify NIZKPoP     %9d  %12.3f %7.3f\n", N, meanVerif, stdVerif)
	fmt.Println("================================================================")
}

func main() {
	N := 1
	fmt.Printf("Testing %d iterations for each algorithm...\n", N)

	testFrodoKEM(zkpop.Frodo640, N)
	testFrodoNIZK(zkpop.Frodo640, N)

	// testFrodoKEM(zkpop.Frodo976, N)
	// testFrodoNIZK(zkpop.Frodo976, N)

	// testFrodoKEM(zkpop.Frodo1344, N)
	// testFrodoNIZK(zkpop.Frodo1344, N)

	fmt.Println("End of testing.")
}
