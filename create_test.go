// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateRecord(t *testing.T) {
	tests := []struct {
		name     string
		jwt      string
		opts     []CreateOption
		expected []string
		err      bool
	}{
		{
			name: "Empty JWT",
		}, {
			name: "Valid JWT with default options",
			jwt:  "header.payload.signature",
			expected: []string{
				"00:header.payload.signature",
			},
		}, {
			name: "Valid JWT with max line length",
			jwt:  "header.payload.signature",
			opts: []CreateOption{
				WithMaxLineLength(10),
			},
			expected: []string{
				"00:header.",
				"01:payload",
				"02:.signat",
				"03:ure",
			},
		}, {
			name: "Valid JWT with max size exceeded",
			jwt:  "header.payload.signature",
			opts: []CreateOption{
				WithMaxSize(10),
			},
			err: true,
		}, {
			name: "Valid JWT with max line length and max size",
			jwt:  "header.payload.signature",
			opts: []CreateOption{
				WithMaxLineLength(10),
				WithMaxSize(30),
			},
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CreateRecord(tt.jwt, tt.opts...)

			if tt.err {
				require.Error(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

/*
func FuzzCreateRecord(f *testing.F) {
	f.Add("header.payload.sig", 100, 255)
	f.Fuzz(func(t *testing.T, jwt string, maxSize int, maxLineLength int) {
		opts := []CreateOption{
			WithMaxSize(maxSize),
			WithMaxLineLength(maxLineLength),
		}

		var local create
		for _, opt := range opts {
			opt.apply(&local)
		}

		lines, err := CreateRecord(jwt, opts...)
		if err != nil {
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}

		var total int
		for _, line := range lines {
			if len(line) > local.maxLineLength {
				t.Errorf("line too long: %s", line)
			}
			total += len(line)
		}

		if total > local.maxSize {
			t.Errorf("total size exceeds max size: %d > %d", total, maxSize)
		}

		// Reassemble the lines and compare to the original JWT.
		reassembled := reassemble(lines)

		if string(jwt) != reassembled {
			t.Errorf("expected %s, got %s", jwt, reassembled)
		}
	})
}
*/
