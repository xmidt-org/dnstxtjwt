// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import "errors"

var (
	ErrInvalidJWT   = errors.New("invalid JWT")
	ErrInvalidInput = errors.New("invalid input")
)
