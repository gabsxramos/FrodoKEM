package main

/*
#cgo CFLAGS: -I../external/KEM-NIZKPoP/frodo-zkpop/src
#cgo LDFLAGS: -L../external/KEM-NIZKPoP/frodo-zkpop/frodo1344 -lfrodo
*/
import "C"

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"zkpop-go/zkpop"
)

import "math"

func stddev(times []float64, mean float64) float64 {
	var sum float64
	for _, t := range times {
		diff := t - mean
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(times)))
}

func testFrodoKEM(N int) {
	fmt.Println("Testing FrodoKEM...")

	var kpTimes, encTimes, decTimes []float64

	// warmup
	pk, sk, err := zkpop.KeyPairFrodo1344()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// ===== KeyPair Timing =====
	startKeypair := time.Now()
	for i := 0; i < N; i++ {
		start := time.Now()
		pk, sk, err = zkpop.KeyPairFrodo1344()
		if err != nil {
			log.Fatalf("Keypair generation failed on iteration %d: %v", i, err)
		}
		kpTimes = append(kpTimes, time.Since(start).Seconds())
	}
	totalKeypair := time.Since(startKeypair).Seconds()

	// warmup
	ct, ss, err := zkpop.EncapsFrodo1344(pk)
	if err != nil {
		log.Fatalf("Failed FrodoKEM encapsulation: %v", err)
	}

	// ===== Encaps Timing =====
	startEncaps := time.Now()
	for i := 0; i < N; i++ {
		start := time.Now()
		ct, ss, err = zkpop.EncapsFrodo1344(pk)
		if err != nil {
			log.Fatalf("Encapsulation failed on iteration %d: %v", i, err)
		}
		encTimes = append(encTimes, time.Since(start).Seconds())
	}
	totalEncaps := time.Since(startEncaps).Seconds()

	// warmup
	css, err := zkpop.DecapsFrodo1344(ct, sk)
	if err != nil || !bytes.Equal(ss, css) {
		log.Fatalf("Failed FrodoKEM decapsulation.")
	}

	// ===== Decaps Timing =====
	startDecaps := time.Now()
	for i := 0; i < N; i++ {
		start := time.Now()
		css, err = zkpop.DecapsFrodo1344(ct, sk)
		if err != nil || !bytes.Equal(ss, css) {
			log.Fatalf("Decapsulation failed on iteration %d", i)
		}
		decTimes = append(decTimes, time.Since(start).Seconds())
	}
	totalDecaps := time.Since(startDecaps).Seconds()

	// ===== Compute Averages & Stddevs =====
	avg := func(times []float64) float64 {
		var sum float64
		for _, t := range times {
			sum += t
		}
		return sum / float64(len(times))
	}

	kpAvg := avg(kpTimes)
	encAvg := avg(encTimes)
	decAvg := avg(decTimes)

	fmt.Printf("KeyPair:  Total = %.4f s, Avg = %.6f s/op, StdDev = %.6f\n", totalKeypair, kpAvg, stddev(kpTimes, kpAvg))
	fmt.Printf("Encaps:   Total = %.4f s, Avg = %.6f s/op, StdDev = %.6f\n", totalEncaps, encAvg, stddev(encTimes, encAvg))
	fmt.Printf("Decaps:   Total = %.4f s, Avg = %.6f s/op, StdDev = %.6f\n", totalDecaps, decAvg, stddev(decTimes, decAvg))
}

func testFrodoKEMNIZKPoP(N int) {
	fmt.Println("Testing FrodoKEM-NIZKPoP...")

	var keygenTimes, verifyTimes []float64

	// warmup
	pk, _, zkpopProof, err := zkpop.KeyPairFrodo1344NIZKPoP()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}
	_ = zkpop.VerifyFrodo1344ZKPop(pk, zkpopProof)

	// ===== KeyGen Timing =====
	startKeygen := time.Now()
	for i := 0; i < N; i++ {
		start := time.Now()
		pk, _, zkpopProof, err = zkpop.KeyPairFrodo1344NIZKPoP()
		if err != nil {
			log.Fatalf("Keypair NIZKPoP failed on iteration %d: %v", i, err)
		}
		keygenTimes = append(keygenTimes, time.Since(start).Seconds())
	}
	totalKeygen := time.Since(startKeygen).Seconds()

	// ===== Verify Timing =====
	startVerify := time.Now()
	for i := 0; i < N; i++ {
		start := time.Now()
		valid := zkpop.VerifyFrodo1344ZKPop(pk, zkpopProof)
		if !valid {
			log.Fatalf("Verification failed on iteration %d", i)
		}
		verifyTimes = append(verifyTimes, time.Since(start).Seconds())
	}
	totalVerify := time.Since(startVerify).Seconds()

	total := totalKeygen + totalVerify

	avg := func(times []float64) float64 {
		var sum float64
		for _, t := range times {
			sum += t
		}
		return sum / float64(len(times))
	}

	keygenAvg := avg(keygenTimes)
	verifyAvg := avg(verifyTimes)

	fmt.Printf("KeyGen:   Total = %.4f s, Avg = %.6f s/op, StdDev = %.6f\n", totalKeygen, keygenAvg, stddev(keygenTimes, keygenAvg))
	fmt.Printf("Verify:   Total = %.4f s, Avg = %.6f s/op, StdDev = %.6f\n", totalVerify, verifyAvg, stddev(verifyTimes, verifyAvg))
	fmt.Printf("Combined: Total = %.4f s, Avg = %.6f s/step (KeyGen+Verify)\n", total, (totalKeygen+totalVerify)/float64(N*2))
}

func main() {
	N := 100
	fmt.Printf("Testing %d iterations for frodo algorithm...\n\n", N)

	testFrodoKEM(N)
	fmt.Println()
	testFrodoKEMNIZKPoP(N)

	fmt.Println("\nEnd of testing.")
}
