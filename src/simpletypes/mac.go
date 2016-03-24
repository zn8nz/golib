package simpletypes

import "bytes"

type MAC [6]byte

// ParseMAC creates a new 48 bit MAC address from the given string.
// The string can be upper and lower case hex with any digit group separators.
func ParseMAC(s string) MAC {
	var buf [6]byte
	j := 0
	hi := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f' {
			if hi {
				buf[j] = atob(c) << 4
			} else {
				buf[j] |= atob(c)
				j++
			}
			hi = !hi
		}
	}
	return MAC(buf)
}

// atob converts ASCII hex digit to its value in the range 0..0xF
func atob(h byte) byte {
	if h > '9' {
		return h&0xF + 9
	}
	return h & 0xF
}

// Format returns a string representation of a MAC address.
// The digits are lowercase hex and can be grouped by inserting a separator sep, which can be "".
// If group = 0 then the separator is inserted between groups of 2 hex characters, or if group = 1
// then between groups of 4 characters. Common parameters are ("-", 0), (":", 0), ("", 0), (".", 1).
func (m MAC) Format(sep string, group int) string {
	const dig = "0123456789abcdef"
	var buf bytes.Buffer
	for i, b := range m {
		buf.WriteByte(dig[b>>4])
		buf.WriteByte(dig[b&0xF])
		if i&group == group {
			buf.WriteString(sep)
		}
	}
	buf.Truncate(buf.Len() - len(sep))
	return buf.String()
}

// OUI returns the Organizationally Unique Identifier or nil.
// If the U/L bit is 0, then the OUI is returned as 3 bytes, else nil is returned.
func (m MAC) OUI() []byte {
	if m[0]&2 == 0 {
		return m[:3]
	}
	return nil
}

// IsLocal indicates whether the address is locally administered.
// It returns true if the U/L bit is 1.
func (m MAC) IsLocal() bool {
	return m[0]&2 != 0
}

// IsMulticast is true if bit 0 of the first byte is 0.
func (m MAC) IsMulticast() bool {
	return m[0]&1 != 0
}
