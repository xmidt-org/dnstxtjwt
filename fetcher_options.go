// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"fmt"
	"net"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type fetcherOptionFunc func(*Fetcher) error

func (f fetcherOptionFunc) apply(r *Fetcher) error {
	return f(r)
}

// WithResolver sets the resolver to use for DNS queries.  If the resolver
// is nil or this option is unset, the net.DefaultResolver is used.
func WithResolver(resolver Resolver) FetcherOption {
	return fetcherOptionFunc(
		func(r *Fetcher) error {
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			r.resolver = resolver
			return nil
		},
	)
}

// WithFQDN sets the FQDN to use for DNS queries.
func WithFQDN(fqdn string) FetcherOption {
	return fetcherOptionFunc(
		func(r *Fetcher) error {
			r.fqdn = fqdn
			return nil
		},
	)
}

// WithTimeout sets the timeout for DNS queries.  Any timeout less than zero
// disable the timeout and wait indefinitely.  The value of 0 sets the default.
// The default timeout is 30s.
func WithTimeout(timeout time.Duration) FetcherOption {
	return fetcherOptionFunc(
		func(r *Fetcher) error {
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			r.timeout = timeout
			return nil
		},
	)
}

// WithParseOptions sets the options to use for JWT parsing.
func WithParseOptions(opts ...jwt.ParseOption) FetcherOption {
	return fetcherOptionFunc(
		func(r *Fetcher) error {
			r.opts = append(r.opts, opts...)
			return nil
		},
	)
}

func validateOptions() FetcherOption {
	return fetcherOptionFunc(
		func(r *Fetcher) error {
			if r.fqdn == "" {
				return fmt.Errorf("%w fqdn must be set", ErrInvalidInput)
			}
			return nil
		},
	)
}
