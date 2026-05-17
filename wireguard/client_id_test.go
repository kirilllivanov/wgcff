package wireguard

import "testing"

func TestFormatClientId(t *testing.T) {
	tests := []struct {
		name     string
		clientId string
		expected string
	}{
		{
			name:     "base64",
			clientId: "AQID",
			expected: "1, 2, 3",
		},
		{
			name:     "base64 url",
			clientId: "-_z7",
			expected: "251, 252, 251",
		},
		{
			name:     "comma separated bytes",
			clientId: "4, 5, 6",
			expected: "4, 5, 6",
		},
		{
			name:     "space separated bytes",
			clientId: "7 8 9",
			expected: "7, 8, 9",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := FormatClientId(test.clientId)
			if err != nil {
				t.Fatal(err)
			}

			if result != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, result)
			}
		})
	}
}

func TestFormatClientIdRejectsInvalidLength(t *testing.T) {
	if _, err := FormatClientId("AQI"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFormatClientIdRejectsInvalidByteValue(t *testing.T) {
	if _, err := FormatClientId("1, 2, 256"); err == nil {
		t.Fatal("expected error")
	}
}
