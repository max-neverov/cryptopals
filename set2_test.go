package cryptopals

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAddPKCSPadding(t *testing.T) {
	actual, err := AddPKCS7Padding([]byte("YELLOW SUBMARINE"), 20)
	if err != nil {
		t.Errorf("Failed to add padding: %v", err)
	}
	expected := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if !bytes.Equal(actual, []byte(expected)) {
		t.Errorf("Wrong padding: %q, expected %q", actual, expected)
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
