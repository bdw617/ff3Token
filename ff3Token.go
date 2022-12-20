package ff3Token

import (
	"errors"
	"strings"
	"unicode"

	"github.com/capitalone/fpe/ff3"
)

// this is a wrapper for the ff3 Cipher
type Cipher struct {
	ff3Cipher ff3.Cipher
}

// not the most elegent solution, but it's short and it illustrates how using a radix of 52 matters.
var (
	postEncryptCipherMap = map[rune]rune{
		'0': 'Q',
		'1': 'R',
		'2': 'S',
		'3': 'T',
		'4': 'U',
		'5': 'V',
		'6': 'W',
		'7': 'X',
		'8': 'Y',
		'9': 'Z',
	}
	preDecryptCipherMap = map[rune]rune{
		'Q': '0',
		'R': '1',
		'S': '2',
		'T': '3',
		'U': '4',
		'V': '5',
		'W': '6',
		'X': '7',
		'Y': '8',
		'Z': '9',
	}
)

// NewCipher initializes a new FF3 Token Cipher for encryption or decryption use key and tweak parameters.
// Radix is not exposed, since for this algorithm it must be 52 (a-zA-Z)
func NewCipher(key []byte, tweak []byte) (Cipher, error) {
	cipher, err := ff3.NewCipher(52, key, tweak)
	return Cipher{ff3Cipher: cipher}, err
}

func transformPostEncrypt(X string) (string, error) {
	var sb strings.Builder
	for _, r := range X {
		if newR, found := postEncryptCipherMap[r]; found {
			sb.WriteRune(newR)
		} else if unicode.IsLetter(r) {
			sb.WriteRune(r)
		} else {
			return "", errors.New("ff3 encryption produced invalid output")
		}
	}
	return sb.String(), nil
}

func transformPreDecrypt(X string) (string, error) {
	var sb strings.Builder
	for _, r := range X {
		if newR, found := preDecryptCipherMap[r]; found {
			sb.WriteRune(newR)
		} else if unicode.IsLetter(r) {
			sb.WriteRune(r)
		} else {
			return "", errors.New("invalid input sent to Decrypt")
		}
	}
	return sb.String(), nil
}

// Encrypt is a wrapper around ff3.Encrypt, but transforms the output to make sure it is only Alpha (not numeric)
func (c Cipher) Encrypt(X string) (string, error) {
	result, err := c.ff3Cipher.Encrypt(X)
	if err != nil {
		return "", err
	}
	return transformPostEncrypt(result)
}

// Decrypt is a wrapper around ff3.Decrypt, but pre-transforms the the input to make sure the it has only valid characters for the ff3 Decrypt
func (c Cipher) Decrypt(X string) (string, error) {
	newX, err := transformPreDecrypt(X)
	if err != nil {
		return newX, err
	}
	return c.ff3Cipher.Decrypt(newX)
}
