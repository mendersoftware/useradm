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
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestUserAdmLogin(t *testing.T) {
	//cases: handler err, no handler err
	testCases := map[string]struct {
		jwtToken      *jwt.Token
		jwtHandlerErr error

		outErr   error
		outToken *jwt.Token
	}{
		"ok": {
			jwtToken:      &jwt.Token{Raw: "dummytoken"},
			jwtHandlerErr: nil,

			outErr: nil,
		},
		"token generation error": {
			jwtToken:      nil,
			jwtHandlerErr: errors.New("token generation error"),

			outErr: errors.New("useradm: failed to generate token: token generation error"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		mockJWTHandler := MockJWTHandler{}
		mockJWTHandler.On("GenerateToken",
			mock.AnythingOfType("string"),
		).Return(tc.jwtToken, tc.jwtHandlerErr)

		useradm := NewUserAdm(&mockJWTHandler)

		token, err := useradm.Login("dontcare", "dontcare")

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tc.jwtToken.Raw, token.Raw)
		}
	}
}
