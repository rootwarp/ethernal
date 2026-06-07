package cli

import "testing"

func TestRedact_Format(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		prefixLen int
		want      string
	}{
		{
			name:      "hex_example",
			s:         "0xabcdef0123",
			prefixLen: 4,
			want:      "0xab… (len=12)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.s, tc.prefixLen); got != tc.want {
				t.Errorf("Redact(%q, %d) = %q, want %q", tc.s, tc.prefixLen, got, tc.want)
			}
		})
	}
}

func TestRedact_Empty(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		prefixLen int
		want      string
	}{
		{
			name:      "empty_string",
			s:         "",
			prefixLen: 4,
			want:      "(empty)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.s, tc.prefixLen); got != tc.want {
				t.Errorf("Redact(%q, %d) = %q, want %q", tc.s, tc.prefixLen, got, tc.want)
			}
		})
	}
}

func TestRedact_ShortString(t *testing.T) {
	// Policy per AC and implementation notes: Redact("0x12", 4) must return a
	// redacted form containing the (len=) suffix; it must never echo the full
	// secret as a bare value (len(s)==prefixLen hits the <= branch producing
	// "0x12 (len=4)" with no … but the trailing tag makes redaction explicit).
	// The "(len=N)" ensures the redaction does NOT silently include the whole
	// secret. This documents the policy for M0.4-6.
	tests := []struct {
		name      string
		s         string
		prefixLen int
		want      string
	}{
		{
			name:      "short_whole_in_prefix",
			s:         "0x12",
			prefixLen: 4,
			want:      "0x12 (len=4)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.s, tc.prefixLen)
			if got != tc.want {
				t.Errorf("Redact(%q, %d) = %q, want %q", tc.s, tc.prefixLen, got, tc.want)
			}
			if got == tc.s {
				t.Errorf("Redact(%q, %d) echoed full secret bare; got %q", tc.s, tc.prefixLen, got)
			}
		})
	}
}
