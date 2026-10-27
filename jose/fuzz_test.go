// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

// Fuzz targets for the jose package's parsers.
//
// Every parser here is reachable with attacker-supplied bytes: a compact JWS/JWE/JWT
// off the wire, a JWKS body fetched from a remote endpoint, or a JWK read from a file.
// Each one decodes before it can decide the input is invalid, so the trust boundary
// these targets sit on is the same one the package's input bounds (MaxCompactSize,
// MaxJwksSize, MaxBlobSize) defend.
//
// The targets are pure, fast and deterministic — no PKCS#11 module or network is
// needed — so they run under `go test -fuzz`. Seed inputs are supplied with f.Add; the
// testdata/fuzz directory is reserved for inputs the engine writes when a target fails.
// Commit those as regression cases: `go test ./...` replays them on every run.
//
// Run one target locally:
//
//	go test -run '^$' -fuzz '^FuzzJweCompactUnmarshal$' -fuzztime 60s ./jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FuzzJweCompactUnmarshal exercises the compact JWE parser: the 5-part split, the
// base64url decoding of each part, the protected-header JSON decode, and the "crit",
// "alg" and "enc" validation that runs before any consumer sees the header.
func FuzzJweCompactUnmarshal(f *testing.F) {
	header := func(h string) string { return base64.RawURLEncoding.EncodeToString([]byte(h)) }

	f.Add("")
	f.Add("a.b.c.d.e")
	f.Add("....")
	f.Add(header(`{"alg":"dir","enc":"A128GCM"}`) + "..aXY.Y3Q.dGFn")
	f.Add(header(`{"alg":"none","enc":"A128GCM"}`) + "..aXY.Y3Q.dGFn")               // unsupported alg
	f.Add(header(`{"alg":"dir","enc":"none"}`) + "..aXY.Y3Q.dGFn")                   // unsupported enc
	f.Add(header(`{"alg":"dir","enc":"A128GCM","crit":["exp"]}`) + "..aXY.Y3Q.dGFn") // crit rejected
	f.Add(header(`not json`) + "..aXY.Y3Q.dGFn")

	f.Fuzz(func(t *testing.T, src string) {
		var jwe JweRfc7516Compact
		if err := jwe.Unmarshal(src); err != nil {
			return
		}
		// A parsed JWE must carry a header gose can act on: Unmarshal validates "alg"
		// and "enc" against the supported sets before returning, so a success that
		// names anything else would mean that gate was bypassed.
		if _, ok := supportedJweAlgs[jwe.ProtectedHeader.Alg]; !ok {
			t.Fatalf("parsed JWE with unsupported alg %q", jwe.ProtectedHeader.Alg)
		}
		if _, ok := supportedJweEncs[jwe.ProtectedHeader.Enc]; !ok {
			t.Fatalf("parsed JWE with unsupported enc %q", jwe.ProtectedHeader.Enc)
		}
		// The received header octets are the AAD and must be preserved verbatim.
		if len(jwe.RawProtectedHeader) == 0 {
			t.Fatal("parsed JWE without a raw protected header")
		}
	})
}

// FuzzJwsUnmarshal exercises the compact JWS parser: the 3-part split, the base64url
// decode of the header and payload, and the strict decode of the signature segment
// (which rejects non-canonical encodings that would yield a second token string).
func FuzzJwsUnmarshal(f *testing.F) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	f.Add("")
	f.Add("a.b.c")
	f.Add("..")
	f.Add(header + "." + payload + "." + sig)
	f.Add(header + "." + payload + "." + sig + "=") // non-canonical signature encoding

	f.Fuzz(func(t *testing.T, src string) {
		var jws Jws
		body, err := jws.Unmarshal(src)
		if err != nil {
			return
		}
		// A success must have produced a header and a body.
		if jws.Header == nil {
			t.Fatal("parsed JWS without an error but with a nil header")
		}
		if body == "" {
			t.Fatal("parsed JWS without an error but with an empty body")
		}
	})
}

// FuzzStrictCompactB64 exercises the canonical-form base64url decoder directly. It is
// the choke point that stops two distinct strings decoding to the same signature bytes.
func FuzzStrictCompactB64(f *testing.F) {
	f.Add("")
	f.Add("AA")
	f.Add("AB") // non-zero trailing bits
	f.Add("aGVsbG8")
	f.Add("aGVsbG8=")

	f.Fuzz(func(t *testing.T, src string) {
		b, err := strictCompactB64(src)
		if err != nil {
			return
		}
		// The whole point of the strict decoder: a success must be the canonical
		// encoding, so re-encoding reproduces the input exactly. This is what stops
		// two distinct strings decoding to the same signature bytes.
		if got := base64.RawURLEncoding.EncodeToString(b); got != src {
			t.Fatalf("accepted non-canonical encoding: %q re-encodes to %q", src, got)
		}
	})
}

// FuzzAudiencesUnmarshalJSON exercises the "aud" claim decoder, which accepts either a
// single string or an array of strings and rejects anything else.
func FuzzAudiencesUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"a"`))
	f.Add([]byte(`["a","b"]`))
	f.Add([]byte(`[1]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, src []byte) {
		var a Audiences
		if err := a.UnmarshalJSON(src); err != nil {
			return
		}
		// A successful decode always yields at least one audience.
		if len(a.Aud) == 0 {
			t.Fatal("decoded audiences without an error but with no members")
		}
	})
}

// FuzzCertificateUnmarshalJSON exercises the "x5c" member decoder: base64 (standard
// alphabet) into DER, then x509.ParseCertificate.
func FuzzCertificateUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`""`))
	f.Add([]byte(`"AAAA"`))
	f.Add([]byte(`"MIIB"`))
	f.Add([]byte(`not-quoted`))

	f.Fuzz(func(t *testing.T, src []byte) {
		var c Certificate
		if err := c.UnmarshalJSON(src); err != nil {
			return
		}
		// A success must have produced a certificate; a nil one would be handed to
		// callers that dereference it.
		if c.Certificate == nil {
			t.Fatal("decoded certificate without an error but with a nil value")
		}
	})
}

// FuzzFingerprintUnmarshalJSON exercises the "x5t" member decoder, which requires the
// decoded digest to be exactly 20 bytes (a SHA-1 thumbprint).
func FuzzFingerprintUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`""`))
	f.Add([]byte(`"AAAAAAAAAAAAAAAAAAAAAAAAAAA"`)) // 20 bytes
	f.Add([]byte(`"AAAA"`))                        // too short
	f.Add([]byte(`not-quoted`))

	f.Fuzz(func(t *testing.T, src []byte) {
		var fp Fingerprint
		if err := fp.UnmarshalJSON(src); err != nil {
			return
		}
		// RFC 7517 §4.9: "x5t" is a SHA-1 thumbprint, so exactly 20 bytes.
		if len(fp.digest) != 20 {
			t.Fatalf("decoded fingerprint of %d bytes, want 20", len(fp.digest))
		}
	})
}

// FuzzJwksUnmarshalJSON exercises the JWKS document decoder: the size bound, the "keys"
// array, and the per-key dispatch through UnmarshalJwk.
func FuzzJwksUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[{"kty":"oct","k":"AAAA"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","n":"AAAA","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"bogus"}]}`))

	f.Fuzz(func(t *testing.T, src []byte) {
		var jwks Jwks
		if err := jwks.UnmarshalJSON(src); err != nil {
			return
		}
		// Every key in a successfully decoded store must be usable.
		for i, k := range jwks.Keys {
			if k == nil {
				t.Fatalf("decoded JWKS with a nil key at index %d", i)
			}
		}
	})
}

// FuzzUnmarshalJwk exercises the JWK entry point: the bounded read, the "kty" dispatch,
// the per-type unmarshal, and the private/public discrimination on "d".
func FuzzUnmarshalJwk(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kty":"oct","k":"AAAA"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AAAA","e":"AQAB"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AAAA","e":"AQAB","d":"AAAA"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","d":"AAAA"}`))
	f.Add([]byte(`{"kty":"bogus"}`))

	f.Fuzz(func(t *testing.T, src []byte) {
		jwk, err := UnmarshalJwk(bytes.NewReader(src))
		if err != nil {
			return
		}
		// A success must yield a concrete key, never a nil interface.
		if jwk == nil {
			t.Fatal("decoded JWK without an error but with a nil value")
		}
	})
}

// FuzzJwkFieldsCheckConsistency exercises the common JWK field validation: the key_ops
// bound and duplicate check, and the x5c/x5t thumbprint consistency check.
func FuzzJwkFieldsCheckConsistency(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"key_ops":["sign","sign"]}`))
	f.Add([]byte(`{"key_ops":["sign","verify"]}`))
	f.Add([]byte(`{"use":"sig","alg":"ES256","kid":"k1"}`))

	f.Fuzz(func(t *testing.T, src []byte) {
		fields := struct {
			*jwkFields
		}{jwkFields: &jwkFields{}}
		if err := json.Unmarshal(src, &fields); err != nil {
			return
		}
		if err := fields.CheckConsistency(); err != nil {
			return
		}
		// A consistent JWK has no duplicate key_ops and stays within the bound.
		if len(fields.KeyOps) > maxKeyOps {
			t.Fatalf("accepted %d key_ops, above the bound of %d", len(fields.KeyOps), maxKeyOps)
		}
		seen := make(map[KeyOps]struct{}, len(fields.KeyOps))
		for _, op := range fields.KeyOps {
			if _, dup := seen[op]; dup {
				t.Fatalf("accepted duplicate key_ops entry %q", op)
			}
			seen[op] = struct{}{}
		}
	})
}
