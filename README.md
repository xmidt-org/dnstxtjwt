# dnstxtjwt

A Go library for creating and using JWTs via DNS TXT records.

[![Build Status](https://github.com/xmidt-org/dnstxtjwt/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/dnstxtjwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/xmidt-org/dnstxtjwt/graph/badge.svg?token=XvcXIaXcmE)](https://codecov.io/gh/xmidt-org/dnstxtjwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/dnstxtjwt)](https://goreportcard.com/report/github.com/xmidt-org/dnstxtjwt)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/dnstxtjwt/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/dnstxtjwt.svg)](https://github.com/xmidt-org/dnstxtjwt/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/dnstxtjwt)](https://pkg.go.dev/github.com/xmidt-org/dnstxtjwt)

## Features

- Able to create a DNS TXT record from a []byte (presumed to be a JWT).
- Client is able to resolve and return the JWT if valid.

## Installation

To install the library, use `go get`:

```sh
go get github.com/xmidt-org/dnstxtjwt
```
