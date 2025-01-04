// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"strings"
)

// reassemble converts the TXT record from the list of encoded lines into
// the expected string of text that we all hope is a legit JWT.  The format
// of the lines in the TXT is:
//
//	00:base64_encoded_JWT_chuck_0
//	01:base64_encoded_JWT_chuck_1
//	nn:base64_encoded_JWT_chuck_nn
//
// Notes:
//   - the index could start at 0 or 1, so accept either.
//   - the lines get concatenated in order and all parts are needed
//   - support over 100 lines if needed
//   - each line can be 255 bytes long including the leading 3 characters
//   - it doesn't really matter if we are missing something because the JWT
//     won't compute and will be discarded.
func reassemble(lines []string) string {
	parts := make(map[int]string, len(lines)+1)

	// The value in the TXT record should be 1 (really 1, but make this tolerant
	// of 0 based indexing)
	parts[0] = ""

	for _, line := range lines {
		segments := strings.Split(line, ":")
		if len(segments) != 2 {
			continue // skip empty or otherwise malformed lines.
		}
		n := getIndexInt(segments[0])
		if n < 0 {
			continue // skip lines that don't have a valid index
		}
		txt := strings.TrimSpace(segments[1])
		parts[n] = txt
	}

	// Since we're re-assembling a JWT that is validated later, do the best
	// we can here, but don't be too strict.
	var buf strings.Builder

	for i := 0; i < len(parts); i++ {
		val, found := parts[i]
		if !found {
			return ""
		}
		buf.WriteString(val)
	}

	return buf.String()
}

func getIndexInt(s string) int {
	var n int

	s = strings.TrimSpace(s)
	for _, c := range s {
		switch c {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			n = n*10 + int(c-'0')
		default:
			return -1
		}
	}

	return n
}
