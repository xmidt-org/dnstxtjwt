// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Fetcher is the main structure for this package.  It holds the configuration
// for the DNS TXT record to fetch and validate.
type Fetcher struct {
	// fqdn is the 'device_id.base_url' based on the input configuration.
	fqdn string

	// resolver is used to supply the resolver to use
	resolver Resolver

	// timeout is the timeout for the DNS query.
	timeout time.Duration

	// opts is the list of options to use for JWT validation.
	opts []jwt.ParseOption
}

// Resolver is the interface that the DNS resolver must implement.
type Resolver interface {
	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTXT(context.Context, string) ([]string, error)
}

// FetcherOption is the interface that all options must implement.
type FetcherOption interface {
	apply(*Fetcher) error
}

// New creates a new Record with the given options.
func New(opts ...FetcherOption) (*Fetcher, error) {
	var r Fetcher

	defaults := []FetcherOption{
		WithResolver(nil),
		WithTimeout(0),
	}

	vadors := []FetcherOption{
		validateOptions(),
	}

	opts = append(defaults, opts...)
	opts = append(opts, vadors...)

	for _, opt := range opts {
		if opt != nil {
			if err := opt.apply(&r); err != nil {
				return nil, err
			}
		}
	}

	return &r, nil
}

// Fetch retrieves the DNS TXT record and validates it as a JWT based on the
// options provided.  Options for validation should be set with the
// WithParseOptions function.
func (r *Fetcher) Fetch(ctx context.Context) (jwt.Token, []byte, error) {
	lines, err := r.fetch(ctx)
	if err != nil {
		return nil, nil, err
	}

	txt := reassemble(lines)

	return r.verify(ctx, txt)
}

func (r Fetcher) fetch(ctx context.Context) ([]string, error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		// Don't wait forever if things are broken.
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	txtChan := make(chan []string)
	errChan := make(chan error)

	go func() {
		lines, err := r.resolver.LookupTXT(ctx, r.fqdn)
		if err != nil {
			errChan <- err
			return
		}
		txtChan <- lines
	}()

	select {
	case lines := <-txtChan:
		return lines, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// verify is a helper function to verify the JWT and return the token with the
// payload as bytes.
func (r *Fetcher) verify(ctx context.Context, txt string) (jwt.Token, []byte, error) {
	input := []byte(txt)

	opts := append(r.opts, jwt.WithContext(ctx))

	token, err := jwt.Parse(input, opts...)
	if err != nil {
		return nil, nil, errors.Join(err, ErrInvalidJWT)
	}

	// Now get the payload as bytes for the return value
	msg, err := jws.Parse(input)
	if err != nil {
		// I don't think this can happen, but just in case.
		return nil, nil, errors.Join(err, ErrInvalidJWT)
	}

	return token, msg.Payload(), nil
}
