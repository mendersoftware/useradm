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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/useradm/jwt"
)

func TestSimpleAuthzAuthorize(t *testing.T) {
	testCases := map[string]struct {
		inResource string
		inAction   string
		inToken    *jwt.Token

		outErr string
	}{
		"ok - create init user with dedicated scope": {
			inResource: "useradm:users:initial",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     ScopeInitialUserCreate,
				},
			},
		},
		"error - use initial scope with incompatible useradm action": {
			inResource: "useradm:some:resource:id",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     ScopeInitialUserCreate,
				},
			},
			outErr: "unauthorized",
		},
		"error - use initial scope outside of useradm": {
			inResource: "otherservice:some:resource:id",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     ScopeInitialUserCreate,
				},
			},
			outErr: "unauthorized",
		},
		"ok - do sth in useradm with the 'all' scope": {
			inResource: "useradm:some:resource:id",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     ScopeAll,
				},
			},
		},
		"ok - do sth in another service with the 'all' scope": {
			inResource: "otherservice:some:resource:id",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     ScopeAll,
				},
			},
		},
		"error: unknown/incompatible scope": {
			inResource: "users:initial",
			inAction:   "POST",
			inToken: &jwt.Token{
				Claims: jwt.Claims{
					Issuer:    "mender",
					ExpiresAt: 2147483647,
					Subject:   "testsubject",
					Scope:     "foobar",
				},
			},
			outErr: "unauthorized",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		authz := &SimpleAuthz{}

		err := authz.Authorize(tc.inToken, tc.inResource, tc.inAction)

		if tc.outErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tc.outErr)
		}
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
