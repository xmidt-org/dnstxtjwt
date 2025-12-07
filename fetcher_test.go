// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/foxcpp/go-mockdns"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/jwskeychain"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

type Set struct {
	resolver Resolver
	provider jwt.ParseOption
	jwt      []byte
	payload  []byte
	fqdn     string
}

func TestFetch(t *testing.T) {
	a, err := MakeTrustedSet("fqdn.example.org", map[string]any{"example": "A"})
	require.NoError(t, err)

	b, err := MakeTrustedSet("fqdn.example.org", map[string]any{"example": "B"})
	require.NoError(t, err)

	pub, err := MakePublicKeySet("fqdn.example.org", map[string]any{"example": "public"})
	require.NoError(t, err)

	var large string
	for i := 0; i < 10000; i++ {
		large += "a"
	}
	giant, err := MakeTrustedSet("fqdn.example.org", map[string]any{"example": large},
		WithMaxLineLength(10),
		WithMaxSize(50*1024),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		options  []FetcherOption
		newErr   bool
		jwt      string
		wantMax  time.Duration
		wantBody []byte
		wantErr  bool
	}{
		{
			name: "working with a trusted JWT",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(a.resolver),
				WithParseOptions(a.provider),
			},
			wantBody: a.payload,
		}, {
			name: "detects an untrusted JWT",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(b.resolver),
				WithParseOptions(a.provider),
			},
			wantErr: true,
		}, {
			name: "working with a public key JWT",
			options: []FetcherOption{
				WithFQDN(pub.fqdn),
				WithResolver(pub.resolver),
				WithParseOptions(pub.provider),
			},
			wantBody: pub.payload,
		}, {
			name: "working with a public key JWT, and extra providers",
			options: []FetcherOption{
				WithFQDN(pub.fqdn),
				WithResolver(pub.resolver),
				WithParseOptions(pub.provider),
				WithParseOptions(a.provider),
			},
			wantBody: pub.payload,
		}, {
			name: "working with a chain trusted JWT, and extra providers",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(a.resolver),
				WithParseOptions(pub.provider),
				WithParseOptions(a.provider),
			},
			wantBody: a.payload,
		}, {
			name: "working with a chain trusted JWT and a large payload",
			options: []FetcherOption{
				WithFQDN(giant.fqdn),
				WithResolver(giant.resolver),
				WithParseOptions(giant.provider),
			},
			wantBody: giant.payload,
		}, {
			name: "fqdn is not valid",
			options: []FetcherOption{
				WithFQDN("invalid.example.org"),
				WithResolver(a.resolver),
				WithParseOptions(a.provider),
			},
			wantErr: true,
		}, {
			name:   "fqdn is missing/empty",
			newErr: true,
		}, {
			name: "error from resolver",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(
					resolverFunc(func(_ context.Context, _ string) ([]string, error) {
						return nil, errors.New("resolver error")
					})),
				WithParseOptions(a.provider),
			},
			wantErr: true,
		}, {
			name: "handles a timeout, with a resolver that provides timeout information",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(
					resolverFunc(func(ctx context.Context, _ string) ([]string, error) {
						<-ctx.Done()
						return nil, &net.DNSError{
							Err:       "context canceled",
							IsTimeout: true,
						}
					})),
				WithTimeout(time.Millisecond * 200),
				WithParseOptions(a.provider),
			},
			wantMax: time.Second,
			wantErr: true,
		}, {
			name: "handles a timeout, with a resolver that doesn't provide timeout information",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(
					resolverFunc(func(ctx context.Context, _ string) ([]string, error) {
						<-ctx.Done()
						return nil, errors.New("context canceled")
					})),
				WithTimeout(time.Millisecond * 200),
				WithParseOptions(a.provider),
			},
			wantMax: time.Second,
			wantErr: true,
		}, {
			name: "handles a timeout, with a resolver that ignores the context",
			options: []FetcherOption{
				WithFQDN(a.fqdn),
				WithResolver(
					resolverFunc(func(_ context.Context, _ string) ([]string, error) {
						time.Sleep(time.Minute)
						return nil, errors.New("context canceled")
					})),
				WithTimeout(time.Millisecond * 200),
				WithParseOptions(a.provider),
			},
			wantMax: time.Second,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fetcher, err := New(tt.options...)

			if tt.newErr {
				assert.Nil(t, fetcher)
				require.Error(t, err)
				return
			}

			require.NotNil(t, fetcher)
			require.NoError(t, err)

			ctx := context.Background()
			before := time.Now()
			token, buf, err := fetcher.Fetch(ctx)
			after := time.Now()

			if tt.wantMax > 0 {
				jitter := time.Millisecond * 100
				assert.WithinDuration(t, before.Add(tt.wantMax), after, tt.wantMax+jitter)
			}

			if tt.wantErr {
				assert.Nil(t, token)
				assert.Nil(t, buf)
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, token)
			assert.NotNil(t, buf)

			assert.Equal(t, tt.wantBody, buf)
		})
	}
}

func MakeTrustedSet(fqdn string, claims map[string]any, opts ...CreateOption) (Set, error) {
	chain, err := keychaintest.New(keychaintest.Desc("leaf<-ica<-root"))
	if err != nil {
		return Set{}, err
	}

	provider, err := jwskeychain.New(jwskeychain.TrustedRoots(chain.Root().Public))
	if err != nil {
		return Set{}, err
	}

	JWT, err := CreateSignedJWT(chain, claims)
	if err != nil {
		return Set{}, err
	}

	record, err := CreateRecord(string(JWT), opts...)
	if err != nil {
		return Set{}, err
	}

	resolver := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			fqdn + ".": {
				TXT: record,
			},
		},
	}

	msg, err := jws.Parse(JWT)
	if err != nil {
		return Set{}, err
	}

	return Set{
		resolver: &resolver,
		provider: jwt.WithKeyProvider(provider),
		jwt:      JWT,
		payload:  msg.Payload(),
		fqdn:     fqdn,
	}, nil
}

func CreateSignedJWT(keychain keychaintest.Chain, claims map[string]any) ([]byte, error) {
	// Build certificate chain.
	var chain cert.Chain
	for _, cert := range keychain.Included() {
		err := chain.AddString(base64.URLEncoding.EncodeToString(cert.Raw))
		if err != nil {
			return nil, err
		}
	}

	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Create headers and set x5c with certificate chain.
	headers := jws.NewHeaders()
	err := headers.Set(jws.X509CertChainKey, &chain)
	if err != nil {
		return nil, err
	}

	// Sign the inner payload with the private key.
	signed, err := jwt.Sign(
		token,
		jwt.WithKey(
			jwa.ES256,
			keychain.Leaf().Private,
			jws.WithProtectedHeaders(headers),
		))
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func MakePublicKeySet(fqdn string, claims map[string]any) (Set, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Set{}, err
	}

	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return Set{}, err
		}
	}

	// Sign the inner payload with the private key.
	JWT, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, priv))
	if err != nil {
		return Set{}, err
	}

	record, err := CreateRecord(string(JWT))
	if err != nil {
		return Set{}, err
	}

	resolver := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			fqdn + ".": {
				TXT: record,
			},
		},
	}

	msg, err := jws.Parse(JWT)
	if err != nil {
		return Set{}, err
	}

	return Set{
		resolver: &resolver,
		provider: jwt.WithKey(jwa.ES256, priv.Public()),
		jwt:      JWT,
		payload:  msg.Payload(),
		fqdn:     fqdn,
	}, nil
}

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}
