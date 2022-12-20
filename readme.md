![GitHub CI](https://github.com/bdw666/ff3Token/actions/workflows/go.yaml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/bdw666/ff3Token.svg)](https://pkg.go.dev/github.com/bdw666/ff3Token)

# FF3Tokkens 

This is a thin layer on top of https://github.com/capitalone/fpe to make encrypted data and decrypted data not share the same dictionary so it's obvious which is encrypted and what is decrypted data. Since FF3 will produce perfectly fine looking decrypted data this provides a layer. The original design for this was done for PCI compliance to minimize the impact of the rest of the system in scope for a PCI audit. (Credit card numbers were the primary use cases, but it can be used for social security numbers, account numbers, or any other data you need to encrypt in place)

## Disclaimer
This is NOT general purpose cryptography, the data to be encrypted with this algorithm is one of many things good engineering should do to properly secure user data. I'm not a cryptographer and have not performed signifiicant crytoanalysis on the algorithm. If you choose to follow this pattern, that's exciting, please let me know! Please do it with the proper experts to review your design. 

## note on FF3
FF3-1 would have been the prefered algorithm but there's no open source in Golang I can find, Hashicorp vault has implemented it as part of their Transform engine, but it's expensive. For a commercial implementation of tokenization, I do recommend having the crypt be in software that meets all your compliance requirements. Then this code is just application code!

## What is this?
This is a simple layer on top of CapitolOne's FF3 algorithm built in Golang. It Enforces input data for Encryption to be numeric, and validates the Decrypted data is numeric. The advantage of this is users and systems can now identify whether or not something is a token (all letters), versus a credit card number (all numbers). Since this is format preserving encryption, the encrypted token fits in the same space as the input data. This allows you to keep the input data as close to source of truth as possible (especially when dealing with fixed with data formats).

## Examples:
4147000000001234 will encrypt to WIrhsWqFLLbFPWpb which will decrypt to 4147000000001234

If you change the key/tweak, you'll get completely different tokens
4147000000001234 --> IjKelwlRMiqljyYq
if you try to decrypt IjKelwlRMiqljyYq with the first key, you'll get an error. Since the radix is 52, and a numeric radix would be 10. Credit card numbers that are 16 digits to generate a token that generates a valid CC number would be 1 in (52/10)^16, which is 1 in 2.858 Billion. 

There are other checks to add in here:
* luhn's algorithm (checksum used for credit card numbers) 
* BIN database for the first 6 digits of a credit card
* regular expressions to validate the length and format for some cards  


