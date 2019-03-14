package cryptopals

import (
	"encoding/hex"
	"io"
	"strings"
)

const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ToBase64 encodes bytes read by given reader and returns base64 encoded string.
//
// The bytes read by the reader are expected to be hexadecimal string.
func ToBase64String(r io.Reader) (string, error) {
	s := make([]byte, 3)
	d := hex.NewDecoder(r)

	var b strings.Builder
	for {
		n, err := d.Read(s)

		if err == io.EOF {
			break
		}

		if err != nil {
			return "", err
		}

		switch n {
		case 1:
			val := uint(s[0]) << 16

			b.WriteByte(base64Table[val>>18&0x3f])
			b.WriteByte(base64Table[val>>12&0x3f])
			b.WriteByte(0x3d)
			b.WriteByte(0x3d)
		case 2:
			val := uint(s[0])<<16 | uint(s[1])<<8

			b.WriteByte(base64Table[val>>18&0x3f])
			b.WriteByte(base64Table[val>>12&0x3f])
			b.WriteByte(base64Table[val>>6&0x3f])
			b.WriteByte(0x3d)
		case 3:
			val := uint(s[0])<<16 | uint(s[1])<<8 | uint(s[2])

			b.WriteByte(base64Table[val>>18&0x3f])
			b.WriteByte(base64Table[val>>12&0x3f])
			b.WriteByte(base64Table[val>>6&0x3f])
			b.WriteByte(base64Table[val&0x3f])
		}
	}

	return b.String(), nil
}
