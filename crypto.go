package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"sort"
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

// EncodeFixedXor returns hexadecimal string represents xor operation on bytes read by given readers.
//
// The bytes read by the readers are expected to be hexadecimal strings of the same size.
// Returns an error if the input is not of the same size or any error encountered while decoding.
func EncodeFixedXor(l, r io.Reader) ([]byte, error) {
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

// DecodeSingleByteXor decodes given byte stream by using xor with a single
// char from `base64Table` and calculating max sentence rate by char frequencies
func DecodeSingleByteXor(r io.Reader) (*DecodeResult, error) {
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

	for i := 32; i < 127; i++ {
		wg.Add(1)
		go decode(append(bs[:0:0], bs...), byte(i))
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
		res, err := DecodeSingleByteXor(bytes.NewReader(scanner.Bytes()))
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

// HammingDistance counts different bits of the given two byte slices.
// Slices must be of the same size.
func HammingDistance(s1, s2 []byte) (int, error) {
	if len(s1) != len(s2) {
		return -1, fmt.Errorf("slices must be of the same size, was %d (%q) and %d (%q)", len(s1), s1, len(s2), s2)
	}
	var b byte
	var res int
	for i := 0; i < len(s1); i++ {
		b = s1[i] ^ s2[i]
		res += bits.OnesCount8(b)
	}
	return res, nil
}

type hammingDistance struct {
	distance float32
	keySize  int
	err      error
}

type hammingDistances []hammingDistance

func (a hammingDistances) Len() int           { return len(a) }
func (a hammingDistances) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a hammingDistances) Less(i, j int) bool { return a[i].distance < a[j].distance }

func FindKeySize(bs []byte) ([]int, error) {
	var wg sync.WaitGroup
	ch := make(chan hammingDistance)
	dst := make([]byte, hex.DecodedLen(len(bs)))
	_, err := hex.Decode(dst, bs)
	if err != nil {
		return nil, err
	}
	for i := 2; i < 42; i++ {
		wg.Add(1)
		go averageHammingDistance(dst, i, ch, &wg)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	ds := make([]hammingDistance, 42)
	for d := range ch {
		if d.err != nil {
			return nil, d.err
		}
		ds[d.keySize] = d
	}
	sort.Sort(hammingDistances(ds))

	res := make([]int, 3)
	for i := 2; i < 5; i++ {
		res[i-2] = ds[i].keySize
	}
	return res, nil
}

func averageHammingDistance(bs []byte, keySize int, ch chan<- hammingDistance, wg *sync.WaitGroup) {
	defer wg.Done()
	// - 1 because we compare one keySize bytes with next, so the last comparison will be
	// len(bs)/keySize - 1 bytes with len(bs)/keySize bytes
	cnt := len(bs)/keySize - 1
	if cnt < 2 {
		// can't calculate average distance if bytes length less than two keySize
		ch <- hammingDistance{float32(keySize), keySize, nil}
		return
	}
	var sum float32
	for i := 0; i < cnt; i++ {
		l := i * keySize
		m := (i + 1) * keySize
		r := (i + 2) * keySize
		d, err := HammingDistance(bs[l:m], bs[m:r])
		if err != nil {
			ch <- hammingDistance{-1, keySize, err}
			return
		}
		sum += float32(d) / float32(keySize)
	}
	ch <- hammingDistance{sum / float32(cnt), keySize, nil}
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
