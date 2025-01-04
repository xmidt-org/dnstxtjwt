// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"fmt"
)

type create struct {
	maxSize       int
	maxLineLength int
}

func (c create) split(buf []byte) (result []string, n int) {
	for idx := 0; len(buf) > 0; idx++ {
		var max int
		switch {
		case len(result) > 999:
			max = c.maxLineLength - len("9999:")
		case len(result) > 99:
			max = c.maxLineLength - len("999:")
		default:
			max = c.maxLineLength - len("99:")
		}

		if len(buf) < max {
			max = len(buf)
		}

		s := string(buf[:max])
		buf = buf[max:]

		line := fmt.Sprintf("%02d:%s", idx, s)
		result = append(result, line)
		n += len(line)
	}

	return result, n
}

type CreateOption interface {
	apply(*create)
}

func CreateRecord(jwt string, opts ...CreateOption) ([]string, error) {
	var c create

	defaults := []CreateOption{
		WithMaxSize(0),
		WithMaxLineLength(0),
	}

	opts = append(defaults, opts...)

	for _, opt := range opts {
		if opt != nil {
			opt.apply(&c)
		}
	}

	lines, n := c.split([]byte(jwt))
	if n > c.maxSize {
		return nil, ErrInvalidInput
	}

	return lines, nil
}
