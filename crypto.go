package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
)

const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var freqs = map[int32]float64{
	' ':  0.04200,
	'.':  0.02100,
	',':  0.00110,
	'\'': 0.00070,
	'a':  0.08167,
	'b':  0.01492,
	'c':  0.02782,
	'd':  0.04253,
	'e':  0.12702,
	'f':  0.02228,
	'g':  0.02015,
	'h':  0.06094,
	'i':  0.06966,
	'j':  0.00153,
	'k':  0.00772,
	'l':  0.04025,
	'm':  0.02406,
	'n':  0.06749,
	'o':  0.07507,
	'p':  0.01929,
	'q':  0.00095,
	'r':  0.05987,
	's':  0.06327,
	't':  0.09056,
	'u':  0.02758,
	'v':  0.00978,
	'w':  0.02360,
	'x':  0.00150,
	'y':  0.01974,
	'z':  0.00074,
}

// DecodeResult holds result of decoding: a sentence and its rate based on char frequencies
type DecodeResult struct {
	Rate     float64
	Sentence []byte
}

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

// FixedXor returns hexadecimal string represents xor operation on bytes read by given readers.
//
// The bytes read by the readers are expected to be hexadecimal strings of the same size.
// Returns an error if the input is not of the same size or any error encountered while decoding.
func FixedXor(l, r io.Reader) ([]byte, error) {
	src, err := decodeHexToBytes(l)
	if err != nil {
		return nil, err
	}

	rb, err := decodeHexToBytes(r)
	if err != nil {
		return nil, err
	}
	if len(src) != len(rb) {
		return nil, fmt.Errorf("arguments (%q, %q)must have the same size", src, rb)
	}

	for i := range src {
		src[i] ^= rb[i]
	}

	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst, nil
}

// SingleByteXorDecipher decodes given byte stream by using xor with a single
// char from `base64Table` and calculating max sentence rate by char frequencies
func SingleByteXorDecipher(r io.Reader) (*DecodeResult, error) {
	bs, err := decodeHexToBytes(r)
	if err != nil {
		return nil, err
	}

	ch := make(chan DecodeResult)
	var wg sync.WaitGroup

	// decode mutates input slice of bytes
	decode := func(in []byte, b byte) {
		defer wg.Done()

		var fr = 0.0
		var nonASCIICharPenalty = 0.05
		for i := range in {
			in[i] ^= b
			if v, ok := freqs[unicode.ToLower(int32(in[i]))]; !ok {
				fr -= nonASCIICharPenalty
			} else {
				fr += v
			}
		}

		ch <- DecodeResult{fr, in}
	}

	for i := range base64Table {
		wg.Add(1)
		go decode(append(bs[:0:0], bs...), base64Table[i])
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	rate := -1.0
	var resBytes []byte
	for r := range ch {
		if rate < r.Rate {
			rate = r.Rate
			resBytes = r.Sentence
		}
	}
	return &DecodeResult{rate, resBytes}, nil
}

// DetectSingleCharacterXor reads from given reader line by line and apply single xor
// with chars from `base64Table`.
// DetectSingleCharacterXor returns the line with the highest rating
func DetectSingleCharacterXor(r io.Reader) (*DecodeResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	rate := -1.0
	var resBytes []byte
	for scanner.Scan() {
		res, err := SingleByteXorDecipher(bytes.NewReader(scanner.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("reading error: %v", err)
		}
		if rate < res.Rate {
			rate = res.Rate
			resBytes = res.Sentence
		}
	}
	return &DecodeResult{rate, resBytes}, nil
}

// EncodeWithRepeatingXor reads from given reader by chunks of length 256 and encodes
// bytes with circular repeating xor with given key and returns hex representation of
// the result.
// EncodeWithRepeatingXor encodes all characters including non printing like '\n'.
func EncodeWithRepeatingXor(key []byte, r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	var res []byte
	var keyIdx int
	lk := len(key)
	p := make([]byte, 256)
	for {
		l, err := br.Read(p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		for i := 0; i < l; i++ {
			p[i] ^= key[keyIdx]
			keyIdx = (keyIdx + 1) % lk
		}
		dst := make([]byte, hex.EncodedLen(l))
		_ = hex.Encode(dst, p[:l])
		res = append(res, dst...)
	}

	return res, nil
}

func decodeHexToBytes(r io.Reader) ([]byte, error) {
	d := hex.NewDecoder(r)
	s := make([]byte, 256)
	var res []byte
	for {
		n, err := d.Read(s)
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}
		res = append(res, s[:n]...)
	}
	return res, nil
}
