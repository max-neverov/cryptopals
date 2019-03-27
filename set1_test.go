package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestToBase64(t *testing.T) {
	base64Tests := []struct {
		in       string
		expected string
	}{
		{"4d616e", "TWFu"},
		{"4d61", "TWE="},
		{"4d", "TQ=="},
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
	}
	for _, tt := range base64Tests {
		actual, err := ToBase64String(strings.NewReader(tt.in))
		if err != nil {
			t.Errorf("Error while converting [%q]: %v", tt.in, err)
		}

		if actual != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, actual)
		}
	}
}

func TestEncodeFixedXor(t *testing.T) {
	l := strings.NewReader("1c0111001f010100061a024b53535009181c")
	r := strings.NewReader("686974207468652062756c6c277320657965")
	actual, err := EncodeFixedXor(l, r)
	if err != nil {
		t.Errorf("Error while %q xor %q: %v", l, r, err)
	}
	expected := []byte("746865206b696420646f6e277420706c6179")
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %q, got %q", expected, actual)
	}
}

func TestDecodeSingleByteXor(t *testing.T) {
	in, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Errorf("Error while decoding input: %v", err)
	}
	actual, err := DecodeSingleByteXor(in)
	if err != nil {
		t.Errorf("Error while decoding %v", err)
	}
	expected := []byte("Cooking MC's like a pound of bacon")
	if !bytes.Equal(actual.Sentence, expected) {
		t.Errorf("Expected %q got %q", expected, actual.Sentence)
	}
}

func TestDetectSingleCharacterXor(t *testing.T) {
	path := "testdata/challenge4.txt"
	in, err := os.Open(path)
	if err != nil {
		t.Errorf("Error while open %q: %v", path, err)
	}
	defer in.Close()
	actual, err := DecodeSingleCharacterXor(in)
	if err != nil {
		t.Errorf("Error while decoding file %q: %v", path, err)
	}
	expected := []byte("Now that the party is jumping\n")
	if !bytes.Equal(actual.Sentence, expected) {
		t.Errorf("Expected %q got %q", expected, actual.Sentence)
	}
}

func TestEncodeWithRepeatingXor(t *testing.T) {
	in := fmt.Sprintf("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

	actual, err := EncodeWithRepeatingXor([]byte("ICE"), strings.NewReader(in))
	if err != nil {
		t.Errorf("Error while encoding: %v", err)
	}

	expected, err := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	if err != nil {
		t.Errorf("Error while decoding input: %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %q got %q", expected, actual)
	}
}

func TestEditDistance(t *testing.T) {
	expected := 37
	actual, err := HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))

	if err != nil {
		t.Error(err)
	}

	if actual != expected {
		t.Errorf("Expected distance 37 got %d", actual)
	}
}

func TestFindKeySize(t *testing.T) {
	s1 := fmt.Sprintf("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

	key1 := []byte("ICE")
	in1, err := EncodeWithRepeatingXor(key1, strings.NewReader(s1))
	if err != nil {
		t.Errorf("Error while encoding: %v", err)
	}

	s2 := fmt.Sprintf("This is. A random\ntest string. Random English, sentence because I said so")

	key2 := []byte("Random")
	in2, err := EncodeWithRepeatingXor(key2, strings.NewReader(s2))
	if err != nil {
		t.Errorf("Error while encoding: %v", err)
	}

	keySizeTests := []struct {
		in       []byte
		expected int
	}{
		{in1, len(key1)},
		{in2, len(key2)},
	}

	for _, tt := range keySizeTests {
		sizes, err := FindKeySize(tt.in)
		if err != nil {
			t.Error(err)
		}

		found := false
		for _, size := range sizes {
			if size == tt.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Key size %d, got %v", tt.expected, sizes)
		}
	}
}

func TestDecodeRepeatingXor(t *testing.T) {
	path := "testdata/challenge6.txt"
	in, err := os.Open(path)
	if err != nil {
		t.Errorf("Error while read %q: %v", path, err)
	}
	defer in.Close()

	path = "testdata/challenge6_decoded.txt"
	bs, err := readFromFile(path)
	if err != nil {
		t.Errorf("Error while decode %q: %v", path, err)
	}

	actual, err := DecodeRepeatingXor(in)
	if err != nil {
		t.Errorf("Error while decode %q: %v", path, err)
	}
	expectedKey := []byte("Terminator X: Bring the noise")
	if !bytes.Equal(actual.Key, expectedKey) {
		t.Errorf("Wrong decoded key: %q. Expected %q", actual.Key, expectedKey)
	}

	for i := range bs {
		if actual.Sentence[i] != bs[i] {
			t.Errorf("Wrong decoded text: %q\n Expected %q", actual.Sentence, bs)
			break
		}
	}
}

func TestDecodeAES128ECB(t *testing.T) {
	path := "testdata/challenge7.txt"
	in, err := os.Open(path)
	if err != nil {
		t.Errorf("Error while read %q: %v", path, err)
	}
	defer in.Close()

	path = "testdata/challenge6_decoded.txt"
	bs, err := readFromFile(path)
	if err != nil {
		t.Errorf("Error while decode %q: %v", path, err)
	}

	actual, err := DecodeAES128ECB([]byte("YELLOW SUBMARINE"), in)
	if err != nil {
		t.Errorf("Errorf while decode AES ECB %v", err)
	}

	if !strings.HasPrefix(string(actual), string(bs)) {
		t.Errorf("Wrong decoded text: %q", actual)
	}
}

func TestDetectAESECB(t *testing.T) {
	path := "testdata/challenge8.txt"
	in, err := os.Open(path)
	if err != nil {
		t.Errorf("Error while read %q: %v", path, err)
	}
	defer in.Close()

	expected := []byte("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
	actual, err := DetectAESECB(in)
	if err != nil {
		t.Errorf("Failed to detect AES ECB: %q", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("Wrong detected line: %q", actual)
	}
}

func readFromFile(path string) ([]byte, error) {
	decoded, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error while read %q: %v", path, err)
	}
	defer decoded.Close()
	scanner := bufio.NewScanner(decoded)
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			// We have a full newline-terminated line.
			return i + 1, data[0 : i+1], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return len(data), data[0 : len(data)-1], nil
		}
		// Request more data.
		return 0, nil, nil
	}
	scanner.Split(split)
	var bs []byte
	for scanner.Scan() {
		bs = append(bs, scanner.Bytes()...)
	}
	return bs, nil
}
