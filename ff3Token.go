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

// after encryption, replace any numbers with letters
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

// before decryption, replace letters with the appropiate numbers (see map)
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

// this could be something overriden, to provide the input validation to this.
// The caller could also perform this, but having this in here demostrates the functionality well.
// things this could do:
// * verify that the number matches Luhn's algorithm (checksum used for credit card numbers)
// * IIN database (BIN), check to see if this number matches a possible credit card number
// * regex, check to see if the input number is in a proper credit card format (which depending on the regex engine [0-9]*, might be faster)
func isNumeric(X string) bool {
	for _, r := range X {
		if unicode.IsNumber(r) == false {
			return false
		}
	}
	return true
}

// NewCipher initializes a new FF3 Token Cipher for encryption or decryption use key and tweak parameters.
// Radix is not exposed, since for this algorithm it must be 52 (a-zA-Z)
func NewCipher(key []byte, tweak []byte) (Cipher, error) {
	cipher, err := ff3.NewCipher(52, key, tweak)
	return Cipher{ff3Cipher: cipher}, err
}

// Encrypt is a wrapper around ff3.Encrypt, but transforms the output to make sure it is only Alpha (not numeric)
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
