package wireguard

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

const clientIdLength = 3

// FormatClientId formats Cloudflare's client_id as WireGuard reserved bytes.
func FormatClientId(clientId string) (string, error) {
	bytes, err := clientIdBytes(clientId)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d, %d, %d", bytes[0], bytes[1], bytes[2]), nil
}

func clientIdBytes(clientId string) ([clientIdLength]byte, error) {
	clientId = strings.TrimSpace(clientId)
	if clientId == "" {
		return [clientIdLength]byte{}, fmt.Errorf("client_id is empty")
	}

	if bytes, err := decodeClientIdBase64(clientId); err == nil {
		return bytes, nil
	}

	return parseClientIdBytes(clientId)
}

func decodeClientIdBase64(clientId string) ([clientIdLength]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(clientId)
		if err != nil {
			continue
		}
		if len(decoded) != clientIdLength {
			return [clientIdLength]byte{}, fmt.Errorf("client_id must decode to %d bytes, got %d", clientIdLength, len(decoded))
		}

		var bytes [clientIdLength]byte
		copy(bytes[:], decoded)
		return bytes, nil
	}

	return [clientIdLength]byte{}, fmt.Errorf("client_id is not valid base64")
}

func parseClientIdBytes(clientId string) ([clientIdLength]byte, error) {
	clientId = strings.Trim(clientId, "[]")
	fields := strings.FieldsFunc(clientId, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	if len(fields) != clientIdLength {
		return [clientIdLength]byte{}, fmt.Errorf("client_id must contain %d byte values, got %d", clientIdLength, len(fields))
	}

	var bytes [clientIdLength]byte
	for i, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil {
			return [clientIdLength]byte{}, fmt.Errorf("client_id byte %q is not a number", field)
		}
		if value < 0 || value > 255 {
			return [clientIdLength]byte{}, fmt.Errorf("client_id byte %q is outside 0-255", field)
		}
		bytes[i] = byte(value)
	}

	return bytes, nil
}
