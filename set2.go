package cryptopals

import "fmt"

// AddPKCS7Padding adds padding to a given keyLen as described https://tools.ietf.org/html/rfc2315#section-10.3
func AddPKCS7Padding(bs []byte, keyLen int) ([]byte, error) {
	l := len(bs)
	p := keyLen % l
	if p == 0 {
		return bs, nil
	}
	if p > 256 {
		return nil, fmt.Errorf("cannot add padding %d - larger than 256", p)
	}
	res := make([]byte, l+p)
	copy(res, bs)
	for i := 0; i < p; i++ {
		res[l+i] = byte(p)
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
