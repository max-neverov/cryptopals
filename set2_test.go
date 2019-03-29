package cryptopals

import (
	"bytes"
	"fmt"
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
