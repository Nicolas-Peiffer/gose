// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

// Fuzz targets for the gose package's byte-to-value entry points.
//
// These are the parsers reachable with attacker-supplied input that do not need a live
// token: a compact JWS handed to LoadJws, and the base64url member decoder used when
// importing a JWK. The token-backed paths (signing, decryption) are out of reach of
// `go test -fuzz`, which requires pure, fast and deterministic targets.
//
// Seed inputs are supplied with f.Add; the testdata/fuzz directory is reserved for
// inputs the engine writes when a target fails. Commit those as regression cases:
// `go test ./...` replays them on every run.
//
// Run one target locally:
//
//	go test -run '^$' -fuzz '^FuzzLoadJws$' -fuzztime 60s .

import (
	"strings"
	"testing"
)

// FuzzLoadJws exercises the compact JWS loader: the 3-part split, the base64url decode
// of the header, body and signature, and the header JSON decode.
func FuzzLoadJws(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add("..")
	f.Add("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln")

	f.Fuzz(func(t *testing.T, src string) {
		header, _, _, payload, _, err := LoadJws(src)
		if err != nil {
			return
		}
		// A success must have produced a header and a payload.
		if header == nil {
			t.Fatal("loaded JWS without an error but with a nil header")
		}
		if payload == nil {
			t.Fatal("loaded JWS without an error but with a nil payload")
		}
		// The payload is the signing input: it must be exactly the first two segments,
		// byte for byte, or verification would cover different octets than were sent.
		parts := strings.SplitN(src, ".", 3)
		if want := strings.Join(parts[:2], "."); string(payload) != want {
			t.Fatalf("payload %q does not match the first two segments %q", payload, want)
		}
	})
}

// FuzzFromBase64 exercises the base64url-to-big.Int decoder used when importing a JWK's
// numeric members (n, e, d, x, y, ...).
func FuzzFromBase64(f *testing.F) {
	f.Add("")
	f.Add("AA")
	f.Add("AQAB")
	f.Add("not base64!")

	f.Fuzz(func(t *testing.T, src string) {
		n, err := fromBase64(src)
		if err != nil {
			return
		}
		// SetBytes interprets the octets as an unsigned big-endian integer, so the
		// result is never negative.
		if n.Sign() < 0 {
			t.Fatalf("decoded a negative value %s from %q", n, src)
		}
	})
}
