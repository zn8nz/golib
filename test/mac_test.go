package t

import (
	. "simpletypes"
	"testing"
)

func TestParseMAC(t *testing.T) {
	tests := []struct {
		input string
		want  [6]byte
	}{
		{"fa-90-D1-aB-12-02", [6]byte{0xfa, 0x90, 0xd1, 0xab, 0x12, 0x02}},
		{"E1:98:00:FF:4B:48", [6]byte{0xe1, 0x98, 0, 0xff, 0x4b, 0x48}},
		{"773FF38BB8CC", [6]byte{0x77, 0x3f, 0xf3, 0x8b, 0xb8, 0xcc}},
		{"abcd.ef01.2345", [6]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45}},
		{"junk23,45,aFb9-12zzzzzzz,0~8", [6]byte{0x23, 0x45, 0xaf, 0xb9, 0x12, 0x08}},
	}
	for _, test := range tests {
		if got := ParseMAC(test.input); got != test.want {
			t.Errorf("ParseMAC(%q) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		sep   string
		group int
		want  string
	}{
		{"-", 0, "fa-90-d1-ab-12-02"},
		{".", 1, "fa90.d1ab.1202"},
		{":", 0, "fa:90:d1:ab:12:02"},
		{"", 0, "fa90d1ab1202"},
		{"", 1, "fa90d1ab1202"},
		{"<>", 0, "fa<>90<>d1<>ab<>12<>02"},
		{" ", 1, "fa90 d1ab 1202"},
	}
	mac := ParseMAC("fa:90:d1:AB:12:02")
	for _, test := range tests {
		if got := mac.Format(test.sep, test.group); got != test.want {
			t.Errorf("F(%v) = %v, want %v", mac, got, test.want)
		}
	}
}

func TestOUI(t *testing.T) {
	// local helper function:
	byteSliceEq := func(a, b []byte) bool {
		if len(a) != len(b) {
			return false
		}
		for i := 0; i < len(a); i++ {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	// test data:
	tests := []struct {
		input MAC
		want  []byte
	}{
		{MAC{0xFD, 0x12, 0x34, 0x56, 0x78, 0x9a}, []byte{0xFD, 0x12, 0x34}},
		{MAC{0x02, 0x12, 0x34, 0x56, 0x78, 0x9a}, nil},
		{MAC{0: 0x01}, []byte{1, 0, 0}},
		{MAC{0: 0x02}, nil},
	}
	// test loop for OUI()
	for i, test := range tests {
		if got := test.input.OUI(); !byteSliceEq(got, test.want) {
			t.Errorf("%d: OUI(%v) = %v, want %v", i, test.input, got, test.want)
		}
	}
	// test loop for IsLocal()
	for i, test := range tests {
		if got := test.input.IsLocal(); got != (test.want == nil) {
			t.Errorf("%d: IsLocal(%v) = %v, want %v", i, test.input, got, test.want)
		}
	}
}

func TestIsMulticast(t *testing.T) {
	tests := []struct {
		input MAC
		want  bool
	}{
		{MAC{0xFE, 0x12, 0x34, 0x56, 0x78, 0x9a}, false},
		{MAC{0xFF, 0x12, 0x34, 0x56, 0x78, 0x9a}, true},
		{MAC{0: 0x01}, true},
		{MAC{0: 0x00}, false},
	}
	for i, test := range tests {
		if got := test.input.IsMulticast(); got != test.want {
			t.Errorf("%d: IsMulticast(%v) = %v, want %v", i, test.input, got, test.want)
		}
	}
}
