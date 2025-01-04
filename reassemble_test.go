// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"testing"
)

func TestReassemble(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected string
	}{
		{
			name: "Valid JWT parts starting from 0",
			lines: []string{
				"00:header",
				"01:.payload.",
				"02:signature",
			},
			expected: "header.payload.signature",
		}, {
			name: "Valid JWT parts starting from 0, missing leading 0",
			lines: []string{
				"0:header",
				"1:.payload.",
				"2:signature",
			},
			expected: "header.payload.signature",
		}, {
			name: "Valid JWT parts starting from 0, with extra spaces",
			lines: []string{
				"00:header  ",
				" 01:  .payload.",
				"02 :  signature ",
			},
			expected: "header.payload.signature",
		}, {
			name: "Valid JWT parts starting from 1",
			lines: []string{
				"01:header",
				"02:.payload.",
				"03:signature",
			},
			expected: "header.payload.signature",
		}, {
			name: "Missing part",
			lines: []string{
				"00:header",
				"02:signature",
			},
			expected: "",
		}, {
			name: "Malformed line, missing colon",
			lines: []string{
				"00:header",
				"01payload",
				"02:signature",
			},
			expected: "",
		}, {
			name: "Malformed line, extra colon",
			lines: []string{
				"00:header",
				"01:p:ayload",
				"02:signature",
			},
			expected: "",
		}, {
			name: "Invalid index",
			lines: []string{
				"00:header",
				"xx:payload",
				"02:signature",
			},
			expected: "",
		}, {
			name:     "Empty input",
			lines:    []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reassemble(tt.lines)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
