// Copyright 2017 Northern.tech AS
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
package mongo

import (
	"context"
	"fmt"
	"testing"
	"time"
	"unsafe"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"

	"github.com/mendersoftware/useradm/model"
)

func TestMongoCreateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	exisitingUsers := []interface{}{
		model.User{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "pretenditsahash",
		},
		model.User{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "pretenditsahash",
		},
	}

	testCases := map[string]struct {
		inUser model.User
		tenant string
		outErr string
	}{
		"ok": {
			inUser: model.User{
				ID:       "1234",
				Email:    "baz@bar.com",
				Password: "correcthorsebatterystaple",
			},
			outErr: "",
		},
		"ok with tenant": {
			inUser: model.User{
				ID:       "1234",
				Email:    "baz@bar.com",
				Password: "correcthorsebatterystaple",
			},
			tenant: "foo",
			outErr: "",
		},
		"duplicate email error": {
			inUser: model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			outErr: "user with a given email already exists",
		},
		"duplicate email error with tenant": {
			inUser: model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			tenant: "foo",
			outErr: "user with a given email already exists",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(exisitingUsers...)
		assert.NoError(t, err)

		pass := tc.inUser.Password
		err = store.CreateUser(ctx, &tc.inUser)

		if tc.outErr == "" {
			//fetch user by id, verify password checks out
			var user model.User
			err := session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).FindId("1234").One(&user)
			assert.NoError(t, err)
			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))

			assert.NoError(t, err)

		} else {
			assert.EqualError(t, err, tc.outErr)
		}

		session.Close()
	}
}

func TestMongoUpdateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	exisitingUsers := []interface{}{
		model.User{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "pretenditsahash",
		},
		model.User{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "pretenditsahash",
		},
	}

	testCases := map[string]struct {
		inUserUpdate model.UserUpdate
		inUserId     string
		tenant       string
		outErr       string
	}{
		"update email and password: ok": {
			inUserUpdate: model.UserUpdate{
				Email:    "baz@bar.com",
				Password: "correcthorsebatterystaple",
			},
			inUserId: "1",
			outErr:   "",
		},
		"update email: ok": {
			inUserUpdate: model.UserUpdate{
				Email: "baz@bar.com",
			},
			inUserId: "1",
			outErr:   "",
		},
		"update password: ok": {
			inUserUpdate: model.UserUpdate{
				Password: "correcthorsebatterystaple",
			},
			inUserId: "1",
			outErr:   "",
		},
		"ok with tenant": {
			inUserUpdate: model.UserUpdate{
				Email:    "baz@bar.com",
				Password: "correcthorsebatterystaple",
			},
			inUserId: "1",
			tenant:   "foo",
			outErr:   "",
		},
		"duplicate email error": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			inUserId: "2",
			outErr:   "user with a given email already exists",
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {

			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			session := db.Session()
			store, err := NewDataStoreMongoWithSession(session)
			assert.NoError(t, err)

			store.EnsureIndexes(ctx, session)
			err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(exisitingUsers...)
			assert.NoError(t, err)

			pass := tc.inUserUpdate.Password
			err = store.UpdateUser(ctx, tc.inUserId, &tc.inUserUpdate)

			if tc.outErr == "" {
				var user model.User
				err := session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).FindId(tc.inUserId).One(&user)
				assert.NoError(t, err)
				if tc.inUserUpdate.Password != "" {
					err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))
					assert.NoError(t, err)
				}
				if tc.inUserUpdate.Email != "" {
					assert.Equal(t, user.Email, tc.inUserUpdate.Email)
				}
			} else {
				assert.EqualError(t, err, tc.outErr)
			}

			session.Close()
		})
	}
}

func TestMongoGetUserByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	existingUsers := []interface{}{
		model.User{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "passwordhash12345",
		},
		model.User{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "passwordhashqwerty",
		},
	}

	testCases := map[string]struct {
		inEmail string
		tenant  string
		outUser *model.User
	}{
		"ok - found 1": {
			inEmail: "foo@bar.com",
			outUser: &model.User{
				ID:       "1",
				Email:    "foo@bar.com",
				Password: "passwordhash12345",
			},
		},
		"ok - found 2": {
			inEmail: "bar@bar.com",
			outUser: &model.User{
				ID:       "2",
				Email:    "bar@bar.com",
				Password: "passwordhashqwerty",
			},
		},
		"ok - found 2 with tenant": {
			inEmail: "bar@bar.com",
			outUser: &model.User{
				ID:       "2",
				Email:    "bar@bar.com",
				Password: "passwordhashqwerty",
			},
		},
		"not found": {
			inEmail: "baz@bar.com",
			outUser: nil,
		},
		"not found with tenant": {
			inEmail: "baz@bar.com",
			tenant:  "foo",
			outUser: nil,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(existingUsers...)
		assert.NoError(t, err)

		user, err := store.GetUserByEmail(ctx, tc.inEmail)

		if tc.outUser != nil {
			assert.Equal(t, *tc.outUser, *user)
		} else {
			assert.Nil(t, user)
			assert.Nil(t, err)
		}

		session.Close()
	}
}

func TestMongoGetUserById(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	existingUsers := []interface{}{
		model.User{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "passwordhash12345",
		},
		model.User{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "passwordhashqwerty",
		},
	}

	testCases := map[string]struct {
		inId    string
		tenant  string
		outUser *model.User
	}{
		"ok - found 1": {
			inId: "1",
			outUser: &model.User{
				ID:    "1",
				Email: "foo@bar.com",
			},
		},
		"ok - found 1 with context": {
			inId:   "1",
			tenant: "foo",
			outUser: &model.User{
				ID:    "1",
				Email: "foo@bar.com",
			},
		},
		"ok - found 2": {
			inId: "2",
			outUser: &model.User{
				ID:    "2",
				Email: "bar@bar.com",
			},
		},
		"not found": {
			inId:    "3",
			outUser: nil,
		},
		"not found with tenant": {
			inId:    "3",
			tenant:  "foo",
			outUser: nil,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(existingUsers...)
		assert.NoError(t, err)

		user, err := store.GetUserById(ctx, tc.inId)

		if tc.outUser != nil {
			assert.Equal(t, *tc.outUser, *user)
		} else {
			assert.Nil(t, user)
			assert.Nil(t, err)
		}

		session.Close()
	}
}

func TestMongoGetUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	ts, err := time.Parse(time.RFC3339, "2017-01-31T16:32:05Z")
	assert.NoError(t, err)

	testCases := map[string]struct {
		inUsers  []interface{}
		outUsers []model.User
		tenant   string
	}{
		"ok: list": {
			inUsers: []interface{}{
				model.User{
					ID:       "1",
					Email:    "foo@bar.com",
					Password: "passwordhash12345",
				},
				model.User{
					ID:        "2",
					Email:     "bar@bar.com",
					Password:  "passwordhashqwerty",
					CreatedTs: &ts,
				},
				model.User{
					ID:        "3",
					Email:     "baz@bar.com",
					Password:  "passwordhash1sdf2345",
					UpdatedTs: &ts,
				},
			},
			outUsers: []model.User{
				{
					ID:    "1",
					Email: "foo@bar.com",
				},
				{
					ID:        "2",
					Email:     "bar@bar.com",
					CreatedTs: &ts,
				},
				{
					ID:        "3",
					Email:     "baz@bar.com",
					UpdatedTs: &ts,
				},
			},
			tenant: "foo",
		},
		"ok: empty": {
			inUsers:  []interface{}{},
			outUsers: []model.User{},
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			t.Logf("test case: %s", name)

			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			session := db.Session()
			store, err := NewDataStoreMongoWithSession(session)
			assert.NoError(t, err)

			if len(tc.inUsers) > 0 {
				err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(tc.inUsers...)
			}

			users, err := store.GetUsers(ctx)
			assert.NoError(t, err)

			// transform times to utc
			// bson encoder uses time.Local before writing to mongo, which can be e.g. 'CET'
			// this won't match with assert.Equal
			for i, _ := range users {
				if users[i].CreatedTs != nil {
					t := users[i].CreatedTs.UTC()
					users[i].CreatedTs = &t
				}
				if users[i].UpdatedTs != nil {
					t := users[i].UpdatedTs.UTC()
					users[i].UpdatedTs = &t
				}
			}

			assert.Equal(t, tc.outUsers, users)

			session.Close()
		})
	}
}

func TestMongoDeleteUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	existingUsers := []interface{}{
		model.User{
			ID:       "1",
			Email:    "foo@bar.com",
			Password: "passwordhash12345",
		},
		model.User{
			ID:       "2",
			Email:    "bar@bar.com",
			Password: "passwordhashqwerty",
		},
	}

	testCases := map[string]struct {
		inId     string
		tenant   string
		outUsers []model.User
	}{
		"ok": {
			inId: "1",
			outUsers: []model.User{
				{
					ID:       "2",
					Email:    "bar@bar.com",
					Password: "passwordhashqwerty",
				},
			},
		},
		"ok - with tenant": {
			inId:   "1",
			tenant: "foo",
			outUsers: []model.User{
				{
					ID:       "2",
					Email:    "bar@bar.com",
					Password: "passwordhashqwerty",
				},
			},
		},
		"ok - not found": {
			inId: "3",
			outUsers: []model.User{
				{
					ID:       "1",
					Email:    "foo@bar.com",
					Password: "passwordhash12345",
				},
				{
					ID:       "2",
					Email:    "bar@bar.com",
					Password: "passwordhashqwerty",
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(existingUsers...)
		assert.NoError(t, err)

		err = store.DeleteUser(ctx, tc.inId)
		assert.NoError(t, err)

		var users []model.User
		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Find(nil).All(&users)
		assert.NoError(t, err)

		assert.Equal(t, tc.outUsers, users)

		session.Close()
	}
}

func TestMongoSaveToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		token  *jwt.Token
		tenant string
	}{
		"ok 1": {
			token: &jwt.Token{
				Id: "id-3",
				Claims: jwt.Claims{
					Audience:  "audience",
					ExpiresAt: 1234,
					ID:        "id-3",
					IssuedAt:  5678,
					Issuer:    "iss-3",
					NotBefore: 7890,
					Subject:   "sub-3",
					Scope:     "scope-3",
					Tenant:    "tenant-3",
					User:      true,
				},
			},
		},
		"ok 2": {
			token: &jwt.Token{
				Id: "id-4",
				Claims: jwt.Claims{
					ExpiresAt: 1234,
					ID:        "id-4",
					IssuedAt:  5678,
					Subject:   "sub-4",
					Tenant:    "tenant-4",
					User:      true,
				},
			},
		},
		"ok 3, MT": {
			token: &jwt.Token{
				Id: "id-3",
				Claims: jwt.Claims{
					Audience:  "audience",
					ExpiresAt: 1234,
					ID:        "id-3",
					IssuedAt:  5678,
					Issuer:    "iss-3",
					NotBefore: 7890,
					Subject:   "sub-3",
					Scope:     "scope-3",
					Tenant:    "tenant-3",
					User:      true,
				},
			},
			tenant: "tenant-1",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		db.Wipe()

		//setup
		ctx := context.Background()
		if tc.tenant != "" {
			ctx = identity.WithContext(ctx, &identity.Identity{
				Tenant: tc.tenant,
			})
		}

		session := db.Session()
		store, err := NewDataStoreMongoWithSession(session)
		assert.NoError(t, err)

		//test
		err = store.SaveToken(ctx, tc.token)
		assert.NoError(t, err)

		var token jwt.Token
		err = session.DB(mstore.DbFromContext(ctx, DbName)).C(DbTokensColl).FindId(tc.token.Claims.ID).One(&token)
		assert.NoError(t, err)

		assert.Equal(t, *tc.token, token)

		session.Close()
	}
}

func TestMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMigrate in short mode.")
	}

	testCases := map[string]struct {
		tenantDbs   []string
		automigrate bool

		version string
		err     string
	}{
		"0.1.0": {
			automigrate: true,
			version:     "0.1.0",
			err:         "",
		},
		"0.1.0, no automigrate": {
			automigrate: false,
			version:     "0.1.0",
			err:         "",
		},
		"1.2.3": {
			automigrate: true,
			version:     "1.2.3",
			err:         "",
		},
		"0.1 error": {
			automigrate: true,
			version:     "0.1",
			err:         "failed to parse service version: failed to parse Version: unexpected EOF",
		},
		"0.1.0, automigrate, multitenant": {
			tenantDbs:   []string{"useradm-tenant1", "useradm-tenant2"},
			automigrate: true,
			version:     "0.1.0",
			err:         "",
		},
		"0.1.0, no automigrate, multitenant": {
			tenantDbs:   []string{"useradm-tenant1", "useradm-tenant2"},
			automigrate: true,
			version:     "0.1.0",
			err:         "",
		},
	}

	for name, tc := range testCases {
		t.Logf("case: %s", name)
		db.Wipe()

		store, err := NewDataStoreMongoWithSession(db.Session())
		assert.NoError(t, err)

		// set up automigration
		if tc.automigrate {
			store = store.WithAutomigrate()
		}

		// set up multitenancy/tenant dbs
		if len(tc.tenantDbs) != 0 {
			store = store.WithMultitenant()

			for _, d := range tc.tenantDbs {
				err := store.session.DB(d).C("foo").Insert(bson.M{"foo": "bar"})
				assert.NoError(t, err)
			}
		}

		ctx := context.Background()

		err = store.Migrate(ctx, tc.version, nil)

		if tc.err != "" {
			assert.EqualError(t, err, tc.err)
		} else {

			// verify migration entry in all databases (>1 if multitenant)
			dbs := []string{DbName}
			if len(tc.tenantDbs) > 0 {
				dbs = tc.tenantDbs
			}

			for _, d := range dbs {
				var out []migrate.MigrationEntry
				err = store.session.DB(d).C(migrate.DbMigrationsColl).Find(nil).All(&out)
				if tc.automigrate {
					assert.Len(t, out, 1)
					assert.NoError(t, err)

					v, _ := migrate.NewVersion(tc.version)
					assert.Equal(t, *v, out[0].Version)
				} else {
					assert.Len(t, out, 0)
				}
			}
		}

		store.session.Close()
	}
}

func TestWithAutomigrate(t *testing.T) {
	db.Wipe()

	session := db.Session()
	defer session.Close()

	store, err := NewDataStoreMongoWithSession(session)
	assert.NoError(t, err)

	new_store := store.WithAutomigrate()

	assert.NotEqual(t, unsafe.Pointer(store), unsafe.Pointer(new_store))
	store.session.Close()
}

func TestWithMultitenant(t *testing.T) {
	db.Wipe()

	session := db.Session()
	defer session.Close()

	store, err := NewDataStoreMongoWithSession(session)
	assert.NoError(t, err)

	new_store := store.WithMultitenant()

	assert.NotEqual(t, unsafe.Pointer(store), unsafe.Pointer(new_store))
}
