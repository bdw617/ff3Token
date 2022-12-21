package ff3Token

import (
	"errors"
	"strings"
	"unicode"
)

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
