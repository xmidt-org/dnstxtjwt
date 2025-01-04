// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

type createOptionFunc func(*create)

func (f createOptionFunc) apply(r *create) {
	f(r)
}

// WithMaxLineLength sets the maximum length of a line in the TXT record.  Any
// value outside the range of 1-254 will be set to 254 (default).
func WithMaxLineLength(length int) CreateOption {
	return createOptionFunc(
		func(c *create) {
			if length <= 0 || length > 254 {
				length = 254
			}
			c.maxLineLength = length
		},
	)
}

// WithMaxSize sets the maximum size of the TXT record.  Any value outside the
// range of 1-65,270 will be set to 15*1024 (default).
func WithMaxSize(size int) CreateOption {
	return createOptionFunc(
		func(c *create) {
			if size <= 0 || size > 65270 {
				size = 15 * 1024
			}
			c.maxSize = size
		},
	)
}
