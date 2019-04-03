package cryptopals

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
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

// DecodeSingleByteXorResult holds result of decoding: a sentence and its rate based on char frequencies and the key it was encoded
type DecodeSingleByteXorResult struct {
	Rate     float64
	Sentence []byte
	Key      byte
}

func (d *DecodeSingleByteXorResult) String() string {
	return fmt.Sprintf("Key=%c; rate=%f; sentence=%q\n", d.Key, d.Rate, d.Sentence)
}

// ToBase64 encodes bytes read by given reader and returns base64 encoded string.
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

// DecodeSingleByteXor decodes given bytes by using xor with a single ASCII
// char from [32, 127] interval and calculating max sentence rate by char frequencies
func DecodeSingleByteXor(bs []byte) (*DecodeSingleByteXorResult, error) {
	ch := make(chan DecodeSingleByteXorResult)
	var wg sync.WaitGroup

	// decode mutates input slice of bytes
	decode := func(in []byte, key byte) {
		defer wg.Done()

		var fr = 0.0
		var nonASCIICharPenalty = 0.05
		for i := range in {
			in[i] ^= key
			if v, ok := freqs[unicode.ToLower(int32(in[i]))]; !ok {
				fr -= nonASCIICharPenalty
			} else {
				fr += v
			}
		}

		ch <- DecodeSingleByteXorResult{fr, in, key}
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
	var key byte
	for r := range ch {
		if rate < r.Rate {
			rate = r.Rate
			resBytes = r.Sentence
			key = r.Key
		}
	}
	return &DecodeSingleByteXorResult{rate, resBytes, key}, nil
}

// DetectSingleCharacterXor reads from given reader line by line hex encoded bytes and apply xor
// with a single ASCII char from [32, 127] interval.
// DecodeSingleCharacterXor returns the decoded line with the highest rating and the key it was encoded
func DecodeSingleCharacterXor(r io.Reader) (*DecodeSingleByteXorResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	rate := -1.0
	var resBytes []byte
	var key byte
	for scanner.Scan() {
		bs := scanner.Bytes()
		dst := make([]byte, hex.DecodedLen(len(bs)))
		if _, err := hex.Decode(dst, bs); err != nil {
			return nil, fmt.Errorf("failed to decode %q: %v", bs, err)
		}
		res, err := DecodeSingleByteXor(dst)
		if err != nil {
			return nil, fmt.Errorf("reading error: %v", err)
		}
		if rate < res.Rate {
			rate = res.Rate
			resBytes = res.Sentence
			key = res.Key
		}
	}
	return &DecodeSingleByteXorResult{rate, resBytes, key}, nil
}

// EncodeWithRepeatingXor reads from given reader by chunks of length 256 and returns encoded
// bytes with circular repeating xor with given key.
// EncodeWithRepeatingXor encodes all characters including non printing like '\n'.
func EncodeWithRepeatingXor(key []byte, bs []byte) ([]byte, error) {
	res := make([]byte, len(bs))
	for i := 0; i < len(bs); i++ {
		res[i] = bs[i] ^ key[i%len(key)]
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

// FindKeySize calculates Hamming distance between chunks of the given slice of different length [2; 42).
// FindKeySize returns 3 chunk sizes with the least Hamming distance.
func FindKeySize(bs []byte) ([]int, error) {
	var wg sync.WaitGroup
	ch := make(chan hammingDistance)

	for i := 2; i < 42; i++ {
		wg.Add(1)
		go averageHammingDistance(bs, i, ch, &wg)
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

type DecodeRepeatingXorResult struct {
	Key      []byte
	Sentence []byte
}

func DecodeRepeatingXor(r io.Reader) (*DecodeRepeatingXorResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	var bs []byte
	for scanner.Scan() {
		bs = append(bs, scanner.Bytes()...)
	}

	dst := make([]byte, base64.StdEncoding.DecodedLen(len(bs)))
	if _, err := base64.StdEncoding.Decode(dst, bs); err != nil {
		return nil, fmt.Errorf("failed to base64 decode %q: %v", bs, err)
	}

	ks, err := FindKeySize(dst)
	if err != nil {
		return nil, err
	}

	var theKey []byte
	max := 0.0
	for i := range ks {
		keySize := ks[i]
		s := make([][]byte, keySize)
		// transpose the blocks: makes a block that is the first byte of every block,
		// and a block that is the second byte of every block, and so on
		for i := 0; i < len(dst); i++ {
			idx := i % keySize
			s[idx] = append(s[idx], dst[i])
		}

		key := make([]byte, keySize)
		sum := 0.0

		for i := 0; i < keySize; i++ {
			d, err := DecodeSingleByteXor(s[i])
			if err != nil {
				return nil, err
			}
			sum += d.Rate
			key[i] = d.Key
		}
		sum = sum / float64(keySize)

		if sum > max {
			theKey = key
			max = sum
		}
	}

	res, err := EncodeWithRepeatingXor(theKey, dst)
	if err != nil {
		return nil, fmt.Errorf("failed to decode with repeating xor: %v", err)
	}

	return &DecodeRepeatingXorResult{theKey, res}, nil
}

// DecodeAESECB decodes text from given reader with given key. Text must be base64 encoded.
// see https://codereview.appspot.com/7860047/patch/23001/24001
func DecodeAESECB(key []byte, r io.Reader) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	var bs []byte
	for scanner.Scan() {
		bs = append(bs, scanner.Bytes()...)
	}
	src := make([]byte, base64.StdEncoding.DecodedLen(len(bs)))
	if _, err := base64.StdEncoding.Decode(src, bs); err != nil {
		return nil, fmt.Errorf("failed to base64 decode %q: %v", bs, err)
	}

	dst := make([]byte, len(src))

	for i := 0; i < len(src)/len(key); i++ {
		b.Decrypt(dst[i*len(key):], src[i*len(key):(i+1)*len(key)])
	}

	return dst, nil
}

func encodeAESECB(key, bs []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encodeAESECB: failed to create cipher block: %v", err)
	}
	dst := make([]byte, len(bs))
	for i := 0; i < len(bs)/len(key); i++ {
		b.Encrypt(dst[i*len(key):], bs[i*len(key):(i+1)*len(key)])
	}
	return dst, nil
}

// DetectAESECB reads from given reader hex encoded line by line and compare bytes of the key size (16).
// DetectAESECB returns the first line with byte blocks repetitions.
func DetectAESECB(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		bs := scanner.Bytes()
		dst := make([]byte, hex.DecodedLen(len(bs)))
		if _, err := hex.Decode(dst, bs); err != nil {
			return nil, fmt.Errorf("failed to decode %q: %v", bs, err)
		}

		if detectAESECB(dst) {
			return bs, nil
		}
	}
	return nil, fmt.Errorf("can't detect AES ECB")
}

func detectAESECB(bs []byte) bool {
	blocks := make(map[string]struct{})
	for i := 0; i < len(bs); i += aes.BlockSize {
		block := bs[i : i+aes.BlockSize]
		if _, ok := blocks[string(block)]; ok {
			return true
		}
		blocks[string(block)] = struct{}{}
	}
	return false
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
