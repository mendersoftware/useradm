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
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUserAdmSignToken(t *testing.T) {
	//cases: handler err, no handler err
	testCases := map[string]struct {
		signed  string
		signErr error

		config UserAdmConfig
	}{
		"ok": {
			signed:  "foo",
			signErr: nil,
		},
		"token sign error": {
			signed:  "",
			signErr: errors.New("token generation error"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		mockJWTHandler := MockJWTHandler{}
		mockJWTHandler.On("ToJWT",
			mock.AnythingOfType("*main.Token"),
		).Return(tc.signed, tc.signErr)

		useradm := NewUserAdm(&mockJWTHandler, nil, tc.config)

		sf := useradm.SignToken()

		assert.NotNil(t, sf)

		signed, err := sf(&Token{})

		if tc.signErr != nil {
			assert.EqualError(t, err, tc.signErr.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tc.signed, signed)
		}
	}

}

func TestUserAdmLoginInitial(t *testing.T) {
	testCases := map[string]struct {
		dbEmpty bool
		dbErr   error

		outErr   error
		outToken *Token

		config UserAdmConfig
	}{
		"initial token": {
			dbEmpty: true,
			dbErr:   nil,

			outErr: nil,
			outToken: &Token{
				Claims: Claims{
					Subject: "initial",
					Scope:   ScopeInitialUserCreate,
				},
			},

			config: UserAdmConfig{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"db error": {
			dbErr: errors.New("db failed"),

			outErr: errors.New("useradm: failed to query database: db failed"),
		},
		"db not empty - no token": {
			outToken: nil,
			outErr:   ErrUnauthorized,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db := &mockDataStore{}
		db.On("IsEmpty").Return(tc.dbEmpty, tc.dbErr)

		useradm := NewUserAdm(nil, db, tc.config)

		token, err := useradm.Login("", "")

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			if tc.outToken != nil && assert.NotNil(t, token) {
				assert.NoError(t, err)
				assert.NotEmpty(t, token.Claims.ID)
				assert.Equal(t, tc.config.Issuer, token.Claims.Issuer)
				assert.Equal(t, tc.outToken.Claims.Scope, token.Claims.Scope)
				assert.WithinDuration(t,
					time.Now().Add(time.Duration(tc.config.ExpirationTime)*time.Second),
					time.Unix(token.Claims.ExpiresAt, 0),
					time.Second)

			}
		}
	}

}
