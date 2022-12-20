package ff3Token

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF3samples.pdf

type testVector struct {
	key        string
	tweak      string
	plaintext  string
	ciphertext string
}

var testVectors = []testVector{
	// simple change in the key, creates a completely different token,
	// this simulates multiple enviornments that can have completely different tokens even if they encrypted the exact same data.
	{
		"EF4359D8D580AA4F7F036D6F04FC6A94",
		"D8E7920AFA330A73",
		"4147000000001234", // simulated Visa card
		"WIrhsWqFLLbFPWpb",
	},
	{
		"EF4359D8D580AA4F7F036D6F04FC6A93",
		"D8E7920AFA330A73",
		"4147000000001234", // simulated Visa card
		"IjKelwlRMiqljyYq",
	},
}

func TestEncrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			ciphertext, err := ff3.Encrypt(testVector.plaintext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if ciphertext != testVector.ciphertext {
				t.Fatalf("\nSample%d\nKey:\t\t%s\nTweak:\t\t%s\nPlaintext:\t%s\nCiphertext:\t%s\nExpected:\t%s", sampleNumber, testVector.key, testVector.tweak, testVector.plaintext, ciphertext, testVector.ciphertext)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			plaintext, err := ff3.Decrypt(testVector.ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if plaintext != testVector.plaintext {
				t.Fatalf("\nSample%d\nKey:\t\t%s\nTweak:\t\t%s\nCiphertext:\t%s\nPlaintext:\t%s\nExpected:\t%s", sampleNumber, testVector.key, testVector.tweak, testVector.ciphertext, plaintext, testVector.plaintext)
			}
		})
	}
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Encrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// Create a new FF3 cipher "object"
	FF3, err := NewCipher(key, tweak)
	if err != nil {
		panic(err)
	}

	original := "890121234567890000"

	// Call the encryption function on an example test vector
	ciphertext, err := FF3.Encrypt(original)
	if err != nil {
		panic(err)
	}

	fmt.Println(ciphertext)
	// Output: OOGkpxFEKMmCufxYul
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Decrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// Create a new FF3 cipher "object"
	FF3, err := NewCipher(key, tweak)
	if err != nil {
		panic(err)
	}

	ciphertext := "OOGkpxFEKMmCufxYul"

	plaintext, err := FF3.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	// Output: 890121234567890000
}

func BenchmarkEncrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff3.Encrypt(testVector.plaintext)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			ff3, err := NewCipher(key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff3.Decrypt(testVector.ciphertext)
			}
		})
	}
}
