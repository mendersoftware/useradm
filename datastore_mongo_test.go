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
	"golang.org/x/crypto/bcrypt"
)

func TestMongoIsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		empty bool
	}{
		"empty": {
			empty: true,
		},
		"not empty": {
			empty: false,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		// Make sure we start test with empty database
		db.Wipe()

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		if !tc.empty {
			// insert anything
			session.DB(DbName).C(DbUsersColl).Insert(tc)
		}

		empty, err := store.IsEmpty()

		assert.Equal(t, tc.empty, empty)
		assert.NoError(t, err)

		// Need to close all sessions to be able to call wipe at next
		// test case
		session.Close()
	}
}

func TestMongoCreateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	exisitingUsers := []interface{}{
		UserModel{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "pretenditsahash",
		},
		UserModel{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "pretenditsahash",
		},
	}

	testCases := map[string]struct {
		inUser UserModel
		outErr string
	}{
		"ok": {
			inUser: UserModel{
				ID:       "1234",
				Email:    "baz@bar.com",
				Password: "correcthorsebatterystaple",
			},
			outErr: "",
		},
		"duplicate email error": {
			inUser: UserModel{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			outErr: "user with a given email already exists",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		err = session.DB(DbName).C(DbUsersColl).Insert(exisitingUsers...)
		assert.NoError(t, err)

		pass := tc.inUser.Password
		err = store.CreateUser(&tc.inUser)

		if tc.outErr == "" {
			//fetch user by id, verify password checks out
			var user UserModel
			err := session.DB(DbName).C(DbUsersColl).FindId("1234").One(&user)
			assert.NoError(t, err)
			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))

			assert.NoError(t, err)

		} else {
			assert.EqualError(t, err, tc.outErr)
		}

		session.Close()
	}
}
