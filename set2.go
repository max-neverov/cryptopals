package cryptopals

import "fmt"

// AddPKCSPadding adds padding to a given keyLen as described https://tools.ietf.org/html/rfc2315#section-10.3
func AddPKCSPadding(bs []byte, keyLen int) ([]byte, error) {
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
