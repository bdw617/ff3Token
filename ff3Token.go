package ff3Token

import (
	"errors"

	fpe "github.com/ubiqsecurity/ubiq-fpe-go"
)

// this is a wrapper for the ff3 Cipher
type Cipher struct {
	cipher *fpe.FF3_1
	tweak  []byte
}

const radixLength = 52

// NewCipher initializes a new FF3-1 Token Cipher for encryption or decryption use key and tweak parameters.
// Radix is not exposed, since for this algorithm it must be 52 [a-zA-Z]
func NewCipher(key []byte, tweak []byte) (Cipher, error) {
	cipher, err := fpe.NewFF3_1(key, tweak, radixLength)
	return Cipher{cipher: cipher, tweak: tweak}, err
}

// Encrypt is a wrapper around ff3.Encrypt, input must be Numeric
// Transforms the output to make sure it is only letters [A-Za-z]+
func (c Cipher) Encrypt(X string) (string, error) {
	if !isNumeric(X) {
		return "", errors.New("invalid input sent to Encrypt (must be numeric)")
	}

	result, err := c.cipher.Encrypt(X, c.tweak)
	if err != nil {
		return "", err
	}
	return transformPostEncrypt(result)
}

// Decrypt is a wrapper around ff3.Decrypt.
// It will pre-transform the content to fit the radix dictionary.
// Post check to make sure the output is fully numeric.
func (c Cipher) Decrypt(X string) (string, error) {
	newX, err := transformPreDecrypt(X)
	if err != nil {
		return newX, err
	}
	decrypted, err := c.cipher.Decrypt(newX, c.tweak)
	if err != nil {
		return "", err
	}

	if !isNumeric(decrypted) {
		return "", errors.New("Decrypt failed to produce numeric output")
	}
	return decrypted, err
}
