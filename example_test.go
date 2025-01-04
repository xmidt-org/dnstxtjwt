// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package dnstxtjwt_test

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/foxcpp/go-mockdns"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/xmidt-org/dnstxtjwt"
	"github.com/xmidt-org/jwskeychain"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

type Set struct {
	resolver dnstxtjwt.Resolver
	provider jwt.ParseOption
	jwt      []byte
}

// MakeTrustSet creates a new trust set with the given claims and FQDN.
// Normally, this the chain is provided to the code through configuration, but
// this function is used to create a trust set for the example.
func MakeTrustSet(fqdn string, claims map[string]any) (Set, error) {
	// Create a keychain with a leaf, intermediate, and root certificate.
	chain, err := keychaintest.New(keychaintest.Desc("leaf<-ica<-root"))
	if err != nil {
		return Set{}, err
	}

	// Create a key provider with the root certificate public key.  You will
	// get the public key from the root certificate in the chain you're provided.
	provider, err := jwskeychain.New(jwskeychain.TrustedRoots(chain.Root().Public))
	if err != nil {
		return Set{}, err
	}

	// Create a signed JWT with the chain and claims.
	JWT, err := CreateSignedJWT(chain, claims)
	if err != nil {
		return Set{}, err
	}

	// Create a DNS TXT record with the JWT.  This is here for the example, but
	// normally you would not need to do this.  The record would be hosted by
	// the DNS server.
	record, err := dnstxtjwt.CreateRecord(string(JWT))
	if err != nil {
		return Set{}, err
	}

	// Create a mock DNS resolver with the record.  This is here for the example,
	// but normally you would not need to do this.  The resolver would be
	// normally be the net.DefaultResolver or one you create.
	resolver := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			fqdn + ".": {
				TXT: record,
			},
		},
	}

	return Set{
		resolver: &resolver,
		provider: jwt.WithKeyProvider(provider),
		jwt:      JWT,
	}, nil
}

// CreateSignedJWT creates a signed JWT with the given keychain and claims.
// Normally, this would be done by the service that is creating the JWT.
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

func Example() {
	set, _ := MakeTrustSet("example.com", map[string]any{"role": "user"})
	fetcher, _ := dnstxtjwt.New(
		dnstxtjwt.WithFQDN("example.com"),
		dnstxtjwt.WithResolver(set.resolver), // normally you would not include this line
		dnstxtjwt.WithParseOptions(set.provider),
	)

	ctx := context.Background()
	token, _, _ := fetcher.Fetch(ctx)

	role, _ := token.Get("role")
	fmt.Println("role:", role)

	// Output:
	// role: user
}
