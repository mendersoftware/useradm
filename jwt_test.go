// Copyright 2016 Mender Software AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestNewJWTHandlerRS256(t *testing.T) {
	privKey := loadPrivKey("crypto/private.pem", t)
	jwtHandler := NewJWTHandlerRS256(privKey, nil)

	assert.NotNil(t, jwtHandler)
	assert.NotNil(t, jwtHandler.log)
}

func TestJWTHandlerRS256GenerateToken(t *testing.T) {
	testCases := map[string]struct {
		privKey      *rsa.PrivateKey
		claims       Claims
		expiresInSec int64
	}{
		"ok": {
			privKey: loadPrivKey("crypto/private.pem", t),
			claims: Claims{
				Issuer:  "Mender",
				Subject: "foo",
			},
			expiresInSec: 3600,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)
		jwtHandler := NewJWTHandlerRS256(tc.privKey, nil)

		raw, err := jwtHandler.ToJWT(&Token{
			Claims: tc.claims,
		})
		assert.NoError(t, err)

		_ = parseGeneratedTokenRS256(t, string(raw), tc.privKey)
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

func parseGeneratedTokenRS256(t *testing.T, token string, key *rsa.PrivateKey) *jwt.Token {
	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method: " + token.Method.Alg())
		}
		return &key.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("can't parse token: %s", err.Error())
	}

	return tokenParsed
}
