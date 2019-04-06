package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math/big"
)

var randomKey = []byte{43, 225, 166, 6, 178, 106, 163, 61, 40, 109, 171, 236, 72, 222, 188, 142}

// AddPKCS7Padding adds padding to a given keyLen as described https://tools.ietf.org/html/rfc2315#section-10.3
func AddPKCS7Padding(bs []byte, keyLen int) ([]byte, error) {
	p := keyLen - len(bs)%keyLen
	if p > 256 {
		return nil, fmt.Errorf("cannot add padding %d - larger than 256", p)
	}

	res := make([]byte, len(bs)+p)
	copy(res, bs)
	for i := len(bs); i < len(bs)+p; i++ {
		res[i] = byte(p)
	}
	return res, nil
}

// ValidatePKCS7Padding throws a error if PKCS#7 padding is invalid.
func ValidatePKCS7Padding(bs []byte) error {
	l := len(bs)
	p := bs[l-1]
	if bs[l-int(p)] != p {
		fmt.Printf("l=%d,p=%d,bs=%d, %c\n", l, p, bs[l-int(p)-1], bs[l-int(p)-1])
		return fmt.Errorf("wrong padding in %q", bs)
	}
	for i := l - int(p); i < l; i++ {
		if bs[i] != p {
			return fmt.Errorf("wrong padding in %q", bs)
		}
	}
	return nil
}

func DecodeAESCBC(bs, iv, key []byte) ([]byte, error) {
	if len(iv) != len(key) {
		return nil, fmt.Errorf("DecodeAESCBC: iv size (%d) should be the same as key size (%d)", len(iv), len(key))
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("DecodeAESCBC: failed to create cipher: %v", err)
	}

	prev := iv
	res := make([]byte, len(bs))
	tmp := make([]byte, len(key))

	for i := 0; i < len(bs); i += len(key) {
		b.Decrypt(tmp, bs[i:])
		tmp, err := EncodeWithRepeatingXor(prev, tmp)
		if err != nil {
			return nil, fmt.Errorf("DecodeAESCBC: failed to xor: %v", err)
		}
		copy(res[i:], tmp)
		prev = bs[i : i+len(key)]
	}
	return res, nil
}

func EncodeAESCBC(bs, iv, key []byte) ([]byte, error) {
	if len(iv) != len(key) {
		return nil, fmt.Errorf("EncodeAESCBC: iv size (%d) should be the same as key size (%d)", len(iv), len(key))
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("EncodeAESCBC: failed to create cipher: %v", err)
	}

	prev := iv
	res := make([]byte, len(bs))

	for i := 0; i < len(bs); i += len(key) {
		tmp, err := EncodeWithRepeatingXor(prev, bs[i:i+len(key)])
		if err != nil {
			return nil, fmt.Errorf("EncodeAESCBC: failed to xor: %v", err)
		}
		b.Encrypt(res[i:], tmp)
		prev = res[i : i+len(key)]
	}
	return res, nil
}

func encryptionOracle(bs []byte) ([]byte, int64, error) {
	paddedText, err := obfuscateWithRandomPrefixAndSuffixAndPad(bs)
	if err != nil {
		return nil, -1, err
	}

	key, err := getNToMRandomBytes(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, -1, err
	}

	d, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return nil, -1, fmt.Errorf("encryptionOracle: failed to roll dice: %v", err)
	}
	var encodedText []byte
	switch d.Int64() {
	case 0:
		//ECB
		encodedText, err = encodeAESECB(key, paddedText)
		if err != nil {
			return nil, -1, err
		}
	case 1:
		//CBC
		iv, err := getNToMRandomBytes(aes.BlockSize, aes.BlockSize)
		if err != nil {
			return nil, -1, err
		}
		encodedText, err = EncodeAESCBC(bs, iv, key)
		if err != nil {
			return nil, -1, err
		}
	}

	return encodedText, d.Int64(), nil
}

func obfuscateWithRandomPrefixAndSuffixAndPad(bs []byte) ([]byte, error) {
	prefix, err := getNToMRandomBytes(5, 10)
	if err != nil {
		return nil, err
	}
	suffix, err := getNToMRandomBytes(5, 10)
	if err != nil {
		return nil, err
	}
	text := append(append(prefix, bs...), suffix...)
	paddedText, err := AddPKCS7Padding(text, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	if err = ValidatePKCS7Padding(paddedText); err != nil {
		return nil, err
	}
	return paddedText, nil
}

func getNToMRandomBytes(n, m int64) ([]byte, error) {
	l, err := rand.Int(rand.Reader, big.NewInt(int64(m-n+1)))
	if err != nil {
		return nil, fmt.Errorf("getNToMRandomBytes: %v", err)
	}
	res := make([]byte, n+l.Int64())
	if _, err = rand.Read(res); err != nil {
		return nil, fmt.Errorf("getNToMRandomBytes: %v", err)
	}
	return res, nil
}

func findECBKeySize(textToDecode []byte) (int, error) {
	bs := make([]byte, 0)
	keySize := -1
	for i := 1; i < 512; i++ {
		bs = append(bs, 'A')
		encodedText, err := encodeECBWithSuffixAndKey(bs, textToDecode, randomKey)
		if err != nil {
			return -1, err
		}
		if detectAESECB(encodedText) {
			keySize = i / 2
			break
		}
	}
	if keySize == -1 {
		return -1, fmt.Errorf("findECBKeySize: failed to detect keySize")
	}
	return keySize, nil
}

func encodeECBWithSuffixAndKey(bs, suffix, key []byte) ([]byte, error) {
	bs = append(bs, suffix...)
	paddedText, err := AddPKCS7Padding(bs, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	encodedText, err := encodeAESECB(key, paddedText)
	if err != nil {
		return nil, err
	}
	return encodedText, nil
}

func decodeECBByteAtATime(textToDecode []byte) ([]byte, error) {
	keySize, err := findECBKeySize(textToDecode)
	if err != nil {
		return nil, err
	}

	var res []byte

	for j := 0; j < len(textToDecode); j += keySize {
		s := bytes.Repeat([]byte{'A'}, keySize)
		for i := keySize; i > 0; i-- {
			b, err := findByteAtIndex(i, textToDecode[j:], s)
			if err != nil {
				return nil, err
			}
			if i == 1 {
				res = append(res, append(s[:keySize-1], b)...)
			} else if keySize-i+1+j == len(textToDecode) {
				res = append(res, append(s[i-1:keySize-1], b)...)
				break
			} else {
				s = append(s[1:keySize-1], b, 'A')
			}
		}
	}
	return res, nil
}

func findByteAtIndex(k int, textToDecode, s []byte) (byte, error) {
	l := len(s)
	m := make(map[string]byte)
	for i := 0; i < 256; i++ {
		s[l-1] = byte(i)
		encodedText, err := encodeECBWithSuffixAndKey(s, textToDecode, randomKey)
		if err != nil {
			return 0, err
		}
		m[string(encodedText[:l])] = byte(i)
	}

	encodedText, err := encodeECBWithSuffixAndKey(s[:k-1], textToDecode, randomKey)
	if err != nil {
		return 0, err
	}
	v, ok := m[string(encodedText[:l])]

	if !ok {
		return 0, fmt.Errorf("failed to decode 16-th byte of %q", s)
	}
	return v, nil
}
