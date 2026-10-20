package crypto

import (
	"bytes"
	"testing"
)

func TestEncodeOTPMessageLayout(t *testing.T) {
	got := encodeOTPMessage("fl", "login", 7, []byte{0xaa, 0xbb})

	want := []byte{}
	want = append(want, 0, 0, 0, 27)
	want = append(want, "go.airlance.org/auth/otp/v1"...)
	want = append(want, 0, 0, 0, 2)
	want = append(want, "fl"...)
	want = append(want, 0, 0, 0, 5)
	want = append(want, "login"...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 7) // generation: uint64, no length prefix

	want = append(want, 0, 0, 0, 2, 0xaa, 0xbb)
	if !bytes.Equal(got, want) {
		t.Errorf("message = %x\nwant      %x", got, want)
	}
}

func TestEncodeOTPMessageIsUnambiguous(t *testing.T) {
	salt := []byte{1, 2, 3}

	pairs := [][2][]byte{
		{encodeOTPMessage("ab", "c", 1, salt), encodeOTPMessage("a", "bc", 1, salt)},
		{encodeOTPMessage("a", "", 1, salt), encodeOTPMessage("", "a", 1, salt)},
		{encodeOTPMessage("f", "p", 1, []byte{1, 2, 3}), encodeOTPMessage("f", "p", 1, []byte{1, 2})},
		{encodeOTPMessage("f", "p", 1, salt), encodeOTPMessage("f", "p", 256, salt)},
		{encodeOTPMessage("f", "p", 1, salt), encodeOTPMessage("f", "p", 1<<56, salt)},
	}
	for i, pair := range pairs {
		if bytes.Equal(pair[0], pair[1]) {
			t.Errorf("pair %d encodes to the same bytes", i)
		}
	}
}
