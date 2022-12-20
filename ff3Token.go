package ff3Token

import (
	"errors"

	"github.com/capitalone/fpe/ff3"
)

// this is a wrapper for the ff3 Cipher
type Cipher struct {
	ff3Cipher ff3.Cipher
}

// NewCipher initializes a new FF3 Token Cipher for encryption or decryption use key and tweak parameters.
// Radix is not exposed, since for this algorithm it must be 52 [a-zA-Z]
func NewCipher(key []byte, tweak []byte) (Cipher, error) {
	cipher, err := ff3.NewCipher(52, key, tweak)
	return Cipher{ff3Cipher: cipher}, err
}

// Encrypt is a wrapper around ff3.Encrypt, input must be Numeric
// Transforms the output to make sure it is only letters [A-Za-z]+
func (c Cipher) Encrypt(X string) (string, error) {
	if !isNumeric(X) {
		return "", errors.New("invalid input sent to Encrypt (must be numeric)")
	}

	result, err := c.ff3Cipher.Encrypt(X)
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
	decrypted, err := c.ff3Cipher.Decrypt(newX)
	if err != nil {
		return "", err
	}

	if !isNumeric(decrypted) {
		return "", errors.New("Decrypt failed to produce numeric output")
	}
	return decrypted, err
}
