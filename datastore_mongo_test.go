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
		store := NewDataStoreMongoWithSession(session)

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
