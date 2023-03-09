// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewJWTHandlerRS256(t *testing.T) {
	privKey := loadPrivKey("../crypto/private.pem", t)
	jwtHandler := NewJWTHandlerRS256(privKey, nil)

	assert.NotNil(t, jwtHandler)
}

func TestJWTHandlerRS256GenerateToken(t *testing.T) {
	testCases := map[string]struct {
		privKey *rsa.PrivateKey
		claims  Claims
	}{
		"ok": {
			privKey: loadPrivKey("../crypto/private.pem", t),
			claims: Claims{
				Issuer:  "Mender",
				Subject: oid.NewUUIDv5("foo"),
				ExpiresAt: Time{
					Time: time.Now().Add(time.Hour),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			jwtHandler := NewJWTHandlerRS256(tc.privKey, nil)

			raw, err := jwtHandler.ToJWT(&Token{
				Claims: tc.claims,
			})
			assert.NoError(t, err)

			_ = parseGeneratedTokenRS256(t, string(raw), tc.privKey)
		})
	}
}

func TestJWTHandlerRS256FromJWT(t *testing.T) {
	testCases := map[string]struct {
		privKey         *rsa.PrivateKey
		fallbackPrivKey *rsa.PrivateKey

		inToken string

		outToken Token
		outErr   error
	}{
		"ok (all claims)": {
			privKey: loadPrivKey("../crypto/private.pem", t),

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleH" +
				"AiOjQ0ODE4OTM5MDAsImlzcyI6Ik1lbmRlciIsImF1ZC" +
				"I6Ik1lbmRlciIsInN1YiI6ImJjYTk1YWRiLWI1ZjEtNT" +
				"Y0Zi05NmE3LTYzNTVjNTJkMWZhNyIsInNjcCI6Im1lbm" +
				"Rlci4qIiwiaWF0IjoxMjM0NTY3LCJqdGkiOiJiOTQ3NT" +
				"MzNi1kZGU2LTU0OTctODA0NC01MWFhOWRkYzAyZjgifQ" +
				".xkL2V6nzPsJaLUezrZg-lSCqH5yrG0ee-79TuaDC7u9" +
				"ty3btT1VhoGdgEmrGUkLRdOAxnY_KI9rNHAkxzuTj8ef" +
				"p6hss8PKC6DHM_Ke_cZH0xRt2V0QjhhZT5QkGFjb60me" +
				"iY5oMQdhXY1rtaFuAvMvPMSZ0Rs4Twy3tuWvws9sekIY" +
				"GWyVV-EGOtheI8_lGXlPSUXc5_0aUJuUNoKyIDFK4Chp" +
				"eYxjyL20U0GPtGPAEKQQkCBqlliBsu1Rdww3a7ephIIs" +
				"Fu6A8BWJpT5hGpiQlKK2hu2MZ9wh94wbcZXJRtlE_BWz" +
				"NLKjV0L1oiaeWKuMGOTQ4TYgKeifWRCm_nw",

			outToken: Token{
				Claims: Claims{
					ID:      oid.NewUUIDv5("someid"),
					Subject: oid.NewUUIDv5("foo"),
					ExpiresAt: Time{
						Time: time.Unix(4481893900, 0),
					},
					IssuedAt: Time{
						Time: time.Unix(1234567, 0),
					},
					Audience: "Mender",
					Issuer:   "Mender",
					Scope:    "mender.*",
				},
			},
		},
		"ok (some claims)": {
			privKey: loadPrivKey("../crypto/private.pem", t),

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW" +
				"IiOiJiY2E5NWFkYi1iNWYxLTU2NGYtOTZhNy02MzU1Yz" +
				"UyZDFmYTciLCJqdGkiOiJiOTQ3NTMzNi1kZGU2LTU0OT" +
				"ctODA0NC01MWFhOWRkYzAyZjgiLCJleHAiOjQ0ODE4OT" +
				"M5MDAsImlzcyI6Ik1lbmRlciIsImF1ZCI6Ik1lbmRlci" +
				"IsInNjcCI6Im1lbmRlci51c2Vycy5pbml0aWFsLmNyZW" +
				"F0ZSIsImlhdCI6MTIzNDU2N30.rzvPALb8-p8PUblS1Q" +
				"LdgWuhVXrZw_kv0xl_qY3OhbKaV1aN2sB8kEea5jdLX0" +
				"ukrKqXD2v9rmqcGNi3pvXqy2zj1EJslHxtSx1BCxzLCB" +
				"l5pu3MhFwTjSlhkyOSL_TTlexcWvw3WCFCnj7D1irwym" +
				"idZPPTvYrq7Zw5WTb_3VcCzf8xrPaXNlaHhIBH265RMW" +
				"_s-9W8R20aFeMHLCNYvsF358sJAXrLI2_NhQlIW_PHy9" +
				"08Tx8F8-GxXqK2vMxa1XPHi_Wr9HScsfz0_6dNtaq8AS" +
				"TCaIibmnTUGe2UYg4xeO66bjKQbsuDXZP_ChOLNzYNmw" +
				"mNfRHRHDT-nnsOWg",

			outToken: Token{
				Claims: Claims{
					ID:      oid.NewUUIDv5("someid"),
					Subject: oid.NewUUIDv5("foo"),
					ExpiresAt: Time{
						Time: time.Unix(4481893900, 0),
					},
					IssuedAt: Time{
						Time: time.Unix(1234567, 0),
					},
					Issuer:   "Mender",
					Audience: "Mender",
					Scope:    "mender.users.initial.create",
				},
			},
		},
		"ok (some claims w. tenant_token)": {
			privKey: loadPrivKey("../crypto/private.pem", t),

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW" +
				"IiOiJiY2E5NWFkYi1iNWYxLTU2NGYtOTZhNy02MzU1Yz" +
				"UyZDFmYTciLCJqdGkiOiJiOTQ3NTMzNi1kZGU2LTU0OT" +
				"ctODA0NC01MWFhOWRkYzAyZjgiLCJleHAiOjQ0ODE4OT" +
				"M5MDAsImlzcyI6Ik1lbmRlciIsInNjcCI6Im1lbmRlci" +
				"4qIiwiaWF0IjoxMjM0NTY3LCJtZW5kZXIudGVuYW50Ij" +
				"oiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIn0.GHw6EC" +
				"1kfeAuB7UkwqwZ6yt25US7lhWXhCG6HYTvXhY1MSaPrL" +
				"0QMQWnAwWYbM7T9o8CEBhKUumJCZ1JiRiC8cKwd9SytL" +
				"UWxuxE4f2qGSyhMpku1yPXQ-mq6s58wrbAf1s0cEU0vT" +
				"gygncp7fnfKcCpg9A3kYZaDnTmqgA63sXlaiSSnPHd-y" +
				"MO5duFb8xqZeoRzkJrKiI2Bh5pMDPNIJkGkGyF37w_8i" +
				"vjKiGB5ph_vm0LyeVjlzEGU7nri5qARE7oJqN1lICgXX" +
				"MzKZXxUB6h-v2vnkIJC0uZR35ddXhXUrpnRWwHn2xSdz" +
				"5QAKAgnr12OlK1fPWrn2xy0cK2Mw",

			outToken: Token{
				Claims: Claims{
					ID:      oid.NewUUIDv5("someid"),
					Subject: oid.NewUUIDv5("foo"),
					ExpiresAt: Time{
						Time: time.Unix(4481893900, 0),
					},
					IssuedAt: Time{
						Time: time.Unix(1234567, 0),
					},
					Issuer: "Mender",
					Scope:  "mender.*",
					Tenant: "000000000000000000000000",
				},
			},
		},
		"ok (fallback not used)": {
			privKey:         loadPrivKey("../crypto/private.pem", t),
			fallbackPrivKey: loadPrivKey("../crypto/private_alternative.pem", t),

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleH" +
				"AiOjQ0ODE4OTM5MDAsImlzcyI6Ik1lbmRlciIsImF1ZC" +
				"I6Ik1lbmRlciIsInN1YiI6ImJjYTk1YWRiLWI1ZjEtNT" +
				"Y0Zi05NmE3LTYzNTVjNTJkMWZhNyIsInNjcCI6Im1lbm" +
				"Rlci4qIiwiaWF0IjoxMjM0NTY3LCJqdGkiOiJiOTQ3NT" +
				"MzNi1kZGU2LTU0OTctODA0NC01MWFhOWRkYzAyZjgifQ" +
				".xkL2V6nzPsJaLUezrZg-lSCqH5yrG0ee-79TuaDC7u9" +
				"ty3btT1VhoGdgEmrGUkLRdOAxnY_KI9rNHAkxzuTj8ef" +
				"p6hss8PKC6DHM_Ke_cZH0xRt2V0QjhhZT5QkGFjb60me" +
				"iY5oMQdhXY1rtaFuAvMvPMSZ0Rs4Twy3tuWvws9sekIY" +
				"GWyVV-EGOtheI8_lGXlPSUXc5_0aUJuUNoKyIDFK4Chp" +
				"eYxjyL20U0GPtGPAEKQQkCBqlliBsu1Rdww3a7ephIIs" +
				"Fu6A8BWJpT5hGpiQlKK2hu2MZ9wh94wbcZXJRtlE_BWz" +
				"NLKjV0L1oiaeWKuMGOTQ4TYgKeifWRCm_nw",

			outToken: Token{
				Claims: Claims{
					ID:      oid.NewUUIDv5("someid"),
					Subject: oid.NewUUIDv5("foo"),
					ExpiresAt: Time{
						Time: time.Unix(4481893900, 0),
					},
					IssuedAt: Time{
						Time: time.Unix(1234567, 0),
					},
					Audience: "Mender",
					Issuer:   "Mender",
					Scope:    "mender.*",
				},
			},
		},
		"ok (fallback used)": {
			privKey:         loadPrivKey("../crypto/private_alternative.pem", t),
			fallbackPrivKey: loadPrivKey("../crypto/private.pem", t),

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleH" +
				"AiOjQ0ODE4OTM5MDAsImlzcyI6Ik1lbmRlciIsImF1ZC" +
				"I6Ik1lbmRlciIsInN1YiI6ImJjYTk1YWRiLWI1ZjEtNT" +
				"Y0Zi05NmE3LTYzNTVjNTJkMWZhNyIsInNjcCI6Im1lbm" +
				"Rlci4qIiwiaWF0IjoxMjM0NTY3LCJqdGkiOiJiOTQ3NT" +
				"MzNi1kZGU2LTU0OTctODA0NC01MWFhOWRkYzAyZjgifQ" +
				".xkL2V6nzPsJaLUezrZg-lSCqH5yrG0ee-79TuaDC7u9" +
				"ty3btT1VhoGdgEmrGUkLRdOAxnY_KI9rNHAkxzuTj8ef" +
				"p6hss8PKC6DHM_Ke_cZH0xRt2V0QjhhZT5QkGFjb60me" +
				"iY5oMQdhXY1rtaFuAvMvPMSZ0Rs4Twy3tuWvws9sekIY" +
				"GWyVV-EGOtheI8_lGXlPSUXc5_0aUJuUNoKyIDFK4Chp" +
				"eYxjyL20U0GPtGPAEKQQkCBqlliBsu1Rdww3a7ephIIs" +
				"Fu6A8BWJpT5hGpiQlKK2hu2MZ9wh94wbcZXJRtlE_BWz" +
				"NLKjV0L1oiaeWKuMGOTQ4TYgKeifWRCm_nw",

			outToken: Token{
				Claims: Claims{
					ID:      oid.NewUUIDv5("someid"),
					Subject: oid.NewUUIDv5("foo"),
					ExpiresAt: Time{
						Time: time.Unix(4481893900, 0),
					},
					IssuedAt: Time{
						Time: time.Unix(1234567, 0),
					},
					Audience: "Mender",
					Issuer:   "Mender",
					Scope:    "mender.*",
				},
			},
		},
		"error - token invalid": {
			privKey: loadPrivKey("../crypto/private.pem", t),

			inToken: "1234123412341234",

			outToken: Token{},
			outErr:   errors.New("token contains an invalid number of segments"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			jwtHandler := NewJWTHandlerRS256(tc.privKey, tc.fallbackPrivKey)

			token, err := jwtHandler.FromJWT(tc.inToken)
			if tc.outErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.outToken.Claims, (*token).Claims)
				assert.NotEmpty(t, token.ID)
			} else {
				assert.EqualError(t, tc.outErr, err.Error())
			}
		})
	}
}

func loadPrivKey(path string, t *testing.T) *rsa.PrivateKey {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.FailNow()
	}

	block, _ := pem.Decode(pem_data)

	if block == nil ||
		block.Type != "RSA PRIVATE KEY" {
		t.FailNow()
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.FailNow()
	}

	return key
}

func parseGeneratedTokenRS256(t *testing.T, token string, key *rsa.PrivateKey) *jwtgo.Token {
	tokenParsed, err := jwtgo.Parse(token, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method: " + token.Method.Alg())
		}
		return &key.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("can't parse token: %s", err.Error())
	}

	return tokenParsed
}
