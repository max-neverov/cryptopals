package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestAddPKCSPadding(t *testing.T) {
	testData := []struct {
		keyLen   int
		expected string
	}{
		{20, "YELLOW SUBMARINE\x04\x04\x04\x04"},
		{16, "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"},
		{10, "YELLOW SUBMARINE\x04\x04\x04\x04"},
	}

	for _, tt := range testData {
		actual, err := AddPKCS7Padding([]byte("YELLOW SUBMARINE"), tt.keyLen)
		if err != nil {
			t.Errorf("Failed to add padding: %v", err)
		}
		if !bytes.Equal(actual, []byte(tt.expected)) {
			t.Errorf("Wrong padding: %q, expected %q", actual, tt.expected)
		}
	}
}

func TestValidatePKCS7Padding(t *testing.T) {
	paddingTests := []struct {
		in       []byte
		expected string
	}{
		{[]byte("ICE ICE BABY\x04\x04\x04\x04"), ""},
		{[]byte("ICE ICE BABY\x05\x05\x05\x05"), fmt.Sprintf("wrong padding in %q", "ICE ICE BABY\x05\x05\x05\x05")},
		{[]byte("ICE ICE BABY\x01\x02\x03\x04"), fmt.Sprintf("wrong padding in %q", "ICE ICE BABY\x01\x02\x03\x04")},
	}

	for _, tt := range paddingTests {
		actual := ValidatePKCS7Padding(tt.in)
		if actual != nil && actual.Error() != tt.expected {
			t.Error(actual)
		}
	}
}

func TestDecodeAESCBC(t *testing.T) {
	path := "testdata/challenge10.txt"

	file, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf("Failed to read the file %v", err)
	}
	src := make([]byte, base64.StdEncoding.DecodedLen(len(file)))
	_, err = base64.StdEncoding.Decode(src, file)
	if err != nil {
		t.Errorf("Failed to decode file %v", err)
	}

	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")
	actual, err := DecodeAESCBC(src, iv, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s", actual)
}

func TestEncodeAESCBC(t *testing.T) {
	expected := []byte("This is the test1234567890......")
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")

	encoded, err := EncodeAESCBC(expected, iv, key)
	if err != nil {
		t.Error(err)
	}
	actual, err := DecodeAESCBC(encoded, iv, key)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("expected %q, actual %q", expected, actual)
	}
}

func TestDetectionOracle(t *testing.T) {
	// at least 2 equal blocks of 16 bytes to detect ECB
	in := bytes.Repeat([]byte("YELLOW SUBMARINE"), 2)
	for i := 0; i < 1000; i++ {
		enc, mode, err := encryptionOracle(in)
		if err != nil {
			t.Fatal(err)
		}
		if detectAESECB(enc) {
			if mode != 0 {
				t.Errorf("mode detected as ECB, but was encoded as CBC")
			}
		}
	}
}

func TestFindECBKeySize(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	bs := []byte("this is a random test string of unknown size")
	paddedText, err := AddPKCS7Padding(bs, aes.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	encodedText, err := encodeAESECB(key, paddedText)
	if err != nil {
		t.Fatal(err)
	}
	keySize, err := findECBKeySize(encodedText)
	if err != nil {
		t.Fatal(err)
	}
	if keySize != len(key) {
		t.Errorf("expected key size %d, got %d", len(key), keySize)
	}
}

func TestDecodeECBByteAtATime(t *testing.T) {
	path := "testdata/challenge12.txt"

	file, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %q: %v", path, err)
	}
	src := make([]byte, base64.StdEncoding.DecodedLen(len(file)))
	_, err = base64.StdEncoding.Decode(src, file)
	if err != nil {
		t.Fatalf("failed to decode file %q: %v", path, err)
	}
	decoded, err := decodeECBByteAtATime(src)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("decoded: %q", decoded)
}
