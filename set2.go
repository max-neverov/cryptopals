package cryptopals

import (
	"crypto/aes"
	"fmt"
)

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
	if bs[l-int(p)-1] == p {
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
