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

	"github.com/stretchr/testify/assert"
)

func TestValidateNew(t *testing.T) {
	testCases := map[string]struct {
		inUser UserModel

		outErr string
	}{
		"email ok, pass ok": {
			inUser: UserModel{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			outErr: "",
		},
		"email invalid, pass ok": {
			inUser: UserModel{
				Email:    "foobar",
				Password: "correcthorsebatterystaple",
			},
			outErr: "Email: foobar does not validate as email;",
		},
		"email ok, pass invalid (empty)": {
			inUser: UserModel{
				Email:    "foo@bar.com",
				Password: "",
			},
			outErr: "password can't be empty",
		},
		"email ok, pass invalid (too short)": {
			inUser: UserModel{
				Email:    "foo@bar.com",
				Password: "asdf",
			},
			outErr: "password too short",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case %s", name)

		err := tc.inUser.ValidateNew()

		if tc.outErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tc.outErr)
		}
	}
}
