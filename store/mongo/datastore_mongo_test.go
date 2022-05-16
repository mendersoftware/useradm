// Copyright 2022 Northern.tech AS
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
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	mopts "go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
)

func assertEqualTokens(t *testing.T, expected, actual *jwt.Token) bool {
	var ret bool
	ret = assert.Equal(t, expected.ID, actual.ID)
	ret = ret && assert.Equal(t, expected.Subject, actual.Subject)
	ret = ret && assert.Equal(t, expected.Audience, actual.Audience)
	ret = ret && assert.WithinDuration(t,
		expected.ExpiresAt.Time,
		actual.ExpiresAt.Time, time.Second)
	ret = ret && assert.WithinDuration(t,
		expected.IssuedAt.Time,
		actual.IssuedAt.Time, time.Second)
	ret = ret && assert.WithinDuration(t,
		expected.NotBefore.Time,
		actual.NotBefore.Time, time.Second)
	ret = ret && assert.Equal(t, expected.Issuer, actual.Issuer)
	ret = ret && assert.Equal(t, expected.Scope, actual.Scope)
	ret = ret && assert.Equal(t, expected.Tenant, actual.Tenant)
	return ret && assert.Equal(t, expected.User, actual.User)
}

func TestPing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestPing in short mode")
	}
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*10)
	defer cancel()
	store, _ := NewDataStoreMongoWithClient(db.Client())
	err := store.Ping(ctx)
	assert.NoError(t, err)
}

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
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			store = store.WithAutomigrate()
			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
				store = store.WithMultitenant()
				err = store.MigrateTenant(ctx, DbVersion, tc.tenant)
				assert.NoError(t, err)
			} else {
				err = store.Migrate(ctx, DbVersion)
				assert.NoError(t, err)
			}

			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				InsertMany(ctx, exisitingUsers)

			assert.NoError(t, err)

			err = store.CreateUser(ctx, &tc.inUser)

			if tc.outErr == "" {
				//fetch user by id, verify password checks out
				var user model.User
				err := client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbUsersColl).
					FindOne(ctx, bson.M{"_id": "1234"}).
					Decode(&user)
				assert.NoError(t, err)
				assert.Equal(t, tc.inUser.Password, user.Password)

			} else {
				assert.EqualError(t, err, tc.outErr)
			}
		})
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
		"error, user not found": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@acme.com",
				Password: "correcthorsebatterystaple",
			},
			inUserId: "3",
			outErr:   store.ErrUserNotFound.Error(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			store = store.WithAutomigrate()
			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
				store = store.WithMultitenant()
				err = store.MigrateTenant(ctx, DbVersion, tc.tenant)
				assert.NoError(t, err)
			} else {
				err = store.Migrate(ctx, DbVersion)
				assert.NoError(t, err)
			}

			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				InsertMany(ctx, exisitingUsers)
			assert.NoError(t, err)

			pass := tc.inUserUpdate.Password
			_, err = store.UpdateUser(ctx, tc.inUserId, &tc.inUserUpdate)

			if tc.outErr == "" {
				var user model.User
				err := client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbUsersColl).
					FindOne(ctx, bson.M{"_id": tc.inUserId}).
					Decode(&user)

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
		})
	}
}

func TestMongoUpdateLoginTs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}
	client := db.Client()
	store, err := NewDataStoreMongoWithClient(client)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	user := &model.User{
		ID:       oid.NewUUIDv5("userid").String(),
		Password: "123456",
		Email:    "foo@bar.bz",
	}
	ctx := context.Background()
	err = store.CreateUser(ctx, user)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	insertedUser, err := store.GetUserById(ctx, user.ID)
	assert.NoError(t, err)
	assert.Nil(t, insertedUser.LoginTs)

	err = store.UpdateLoginTs(ctx, user.ID)
	assert.NoError(t, err)
	resultUser, err := store.GetUserById(ctx, user.ID)
	assert.NoError(t, err)
	if assert.NotNil(t, resultUser.LoginTs) {
		assert.WithinDuration(
			t, time.Now(), *resultUser.LoginTs, time.Second*10,
		)
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
		inEmail model.Email
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
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				InsertMany(ctx, existingUsers)
			assert.NoError(t, err)

			user, err := store.GetUserByEmail(ctx, tc.inEmail)

			if tc.outUser != nil {
				assert.Equal(t, *tc.outUser, *user)
			} else {
				assert.Nil(t, user)
				assert.Nil(t, err)
			}
		})
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
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				InsertMany(ctx, existingUsers)
			assert.NoError(t, err)

			user, err := store.GetUserById(ctx, tc.inId)

			if tc.outUser != nil {
				assert.Equal(t, *tc.outUser, *user)
			} else {
				assert.Nil(t, user)
				assert.Nil(t, err)
			}
		})
	}
}

func TestMongoGetTokenById(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}
	existing := bson.A{
		&jwt.Token{
			Claims: jwt.Claims{
				ID:        oid.NewUUIDv5("id-1"),
				Subject:   oid.NewUUIDv5("sub-1"),
				Audience:  "audience",
				ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour)},
				IssuedAt:  jwt.Time{Time: time.Now()},
				Issuer:    "iss-1",
				NotBefore: jwt.Time{Time: time.Unix(7890, 0)},
				Scope:     "scope-1",
				Tenant:    "tenantID1",
				User:      true,
			},
		},
		&jwt.Token{
			Claims: jwt.Claims{
				ID:        oid.NewUUIDv5("id-2"),
				Subject:   oid.NewUUIDv5("sub-2"),
				Audience:  "audience",
				ExpiresAt: jwt.Time{Time: time.Now().Add(time.Hour)},
				IssuedAt:  jwt.Time{Time: time.Now()},
				Issuer:    "iss-2",
				NotBefore: jwt.Time{Time: time.Unix(7890, 0)},
				Scope:     "scope-2",
				Tenant:    "tenantID2",
				User:      true,
			},
		},
	}

	testCases := map[string]struct {
		id       string
		tenant   string
		outToken *jwt.Token
	}{
		"ok - found 1": {
			id:       "id-1",
			outToken: existing[0].(*jwt.Token),
		},
		"ok - found 1, MT": {
			id:       "id-1",
			tenant:   "tenantID1",
			outToken: existing[0].(*jwt.Token),
		},
		"ok - found 2": {
			id:       "id-2",
			outToken: existing[1].(*jwt.Token),
		},
		"not found": {
			id:       "id-3",
			outToken: nil,
		},
		"not found, MT": {
			id:       "id-3",
			tenant:   "tenantID1",
			outToken: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			t.Log(existing[0])
			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbTokensColl).
				InsertMany(ctx, existing)
			assert.NoError(t, err)

			token, err := store.GetTokenById(ctx, oid.NewUUIDv5(tc.id))

			if tc.outToken != nil {
				assertEqualTokens(t, tc.outToken, token)
			} else {
				assert.Nil(t, token)
				assert.Nil(t, err)
			}
		})
	}
}

func TestMongoGetUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	ts, err := time.Parse(time.RFC3339, "2017-01-31T16:32:05Z")
	assert.NoError(t, err)

	testCases := map[string]struct {
		ctx      context.Context
		inUsers  []interface{}
		outUsers []model.User
		filter   model.UserFilter
		error    error
	}{
		"ok: list": {
			ctx: func() context.Context {
				ctx := context.Background()
				return identity.WithContext(ctx,
					&identity.Identity{
						Tenant: "foo",
					},
				)
			}(),
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
		},
		"ok: with filter": {
			ctx: context.Background(),
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
					UpdatedTs: func() *time.Time {
						t := ts.Add(time.Minute)
						return &t
					}(),
				},
				model.User{
					ID:        "3",
					Email:     "baz@bar.com",
					Password:  "passwordhash1sdf2345",
					UpdatedTs: &ts,
				},
			},
			filter: model.UserFilter{
				ID: []string{"1", "2"},
				Email: []model.Email{
					"foo@bar.com",
					"bar@bar.com",
					"baz@bar.com",
					"user@acme.io",
				},
				CreatedAfter: func() *time.Time {
					t := ts.Add(-time.Hour)
					return &t
				}(),
				CreatedBefore: func() *time.Time {
					t := ts.Add(time.Hour)
					return &t
				}(),
				UpdatedAfter: func() *time.Time {
					t := ts.Add(-time.Hour)
					return &t
				}(),
				UpdatedBefore: func() *time.Time {
					t := ts.Add(time.Hour)
					return &t
				}(),
			},

			outUsers: []model.User{
				{
					ID:        "2",
					Email:     "bar@bar.com",
					CreatedTs: &ts,
					UpdatedTs: func() *time.Time {
						t := ts.Add(time.Minute)
						return &t
					}(),
				},
			},
		},
		"ok: empty": {
			ctx:      context.Background(),
			inUsers:  []interface{}{},
			outUsers: []model.User{},
		},
		"error: context canceled": {
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(
					context.Background(),
				)
				cancel()
				return ctx
			}(),
			inUsers: []interface{}{
				model.User{
					ID:       "1",
					Email:    "foo@bar.com",
					Password: "passwordhash12345",
				},
			},
			error: errors.New("store: failed to fetch users"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			db.Wipe()

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if len(tc.inUsers) > 0 {
				_, err = client.
					Database(mstore.DbFromContext(tc.ctx, DbName)).
					Collection(DbUsersColl).
					InsertMany(context.Background(), tc.inUsers)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
			}

			users, err := store.GetUsers(tc.ctx, tc.filter)
			if tc.error != nil {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.error.Error())
				}
			} else {
				assert.NoError(t, err)

				// transform times to utc
				// bson encoder uses time.Local before writing
				// to mongo, which can be e.g. 'CET'
				// this won't match with assert.Equal
				for i := range users {
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
			}
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
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			_, err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				InsertMany(ctx, existingUsers)
			assert.NoError(t, err)

			err = store.DeleteUser(ctx, tc.inId)
			assert.NoError(t, err)

			var users []model.User
			c, err := client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbUsersColl).
				Find(ctx, bson.M{})

			assert.NoError(t, err)

			err = c.All(ctx, &users)
			assert.NoError(t, err)

			assert.Equal(t, tc.outUsers, users)
		})
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
				Claims: jwt.Claims{
					ID:       oid.NewUUIDv5("id-3"),
					Subject:  oid.NewUUIDv5("sub-3"),
					Audience: "audience",
					ExpiresAt: jwt.Time{
						Time: time.Now().Add(time.Hour),
					},
					IssuedAt: jwt.Time{Time: time.Now()},
					Issuer:   "iss-3",
					NotBefore: jwt.Time{
						Time: time.Unix(7890, 0),
					},
					Scope:  "scope-3",
					Tenant: "tenantID3",
					User:   true,
				},
			},
		},
		"ok 2": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("id-4"),
					Subject: oid.NewUUIDv5("sub-4"),
					ExpiresAt: jwt.Time{
						Time: time.Now().Add(time.Hour),
					},
					IssuedAt: jwt.Time{Time: time.Now()},
					Tenant:   "tenantID4",
					User:     true,
				},
			},
		},
		"ok 3, MT": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:       oid.NewUUIDv5("id-3"),
					Subject:  oid.NewUUIDv5("sub-3"),
					Audience: "audience",
					ExpiresAt: jwt.Time{
						Time: time.Now().Add(time.Hour),
					},
					IssuedAt: jwt.Time{Time: time.Now()},
					Issuer:   "iss-3",
					NotBefore: jwt.Time{
						Time: time.Unix(7890, 0),
					},
					Scope:  "scope-3",
					Tenant: "tenantID3",
					User:   true,
				},
			},
			tenant: "tenantID1",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			//setup
			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			//test
			err = store.SaveToken(ctx, tc.token)
			assert.NoError(t, err)

			var token jwt.Token
			err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbTokensColl).
				FindOne(ctx, bson.M{"_id": tc.token.Claims.ID}).
				Decode(&token)

			assert.NoError(t, err)

			assertEqualTokens(t, tc.token, &token)
		})
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
		DbVersion: {
			automigrate: true,
			version:     DbVersion,
			err:         "",
		},
		DbVersion + ", no automigrate": {
			automigrate: false,
			version:     DbVersion,
			err:         "",
		},
		"0.1 error": {
			automigrate: true,
			version:     "0.1",
			err:         "failed to parse service version: failed to parse Version: unexpected EOF",
		},
		DbVersion + ", automigrate, multitenant": {
			tenantDbs:   []string{"useradm-tenant1", "useradm-tenant2"},
			automigrate: true,
			version:     DbVersion,
			err:         "",
		},
		DbVersion + ", no automigrate, multitenant": {
			tenantDbs:   []string{"useradm-tenant1", "useradm-tenant2"},
			automigrate: true,
			version:     DbVersion,
			err:         "",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			store, err := NewDataStoreMongoWithClient(db.Client())
			assert.NoError(t, err)

			// set up automigration
			if tc.automigrate {
				store = store.WithAutomigrate()
			}

			// set up multitenancy/tenant dbs
			if len(tc.tenantDbs) != 0 {
				store = store.WithMultitenant()

				for _, d := range tc.tenantDbs {
					_, err := store.client.
						Database(d).
						Collection("foo").
						InsertOne(context.TODO(), bson.M{"foo": "bar"})
					assert.NoError(t, err)
				}
			}

			ctx := context.Background()

			err = store.Migrate(ctx, tc.version)

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
					findOpts := mopts.Find().SetSort(bson.D{
						{Key: "version.major", Value: -1},
						{Key: "version.minor", Value: -1},
						{Key: "version.patch", Value: -1},
					})
					c, err := store.client.
						Database(d).
						Collection(migrate.DbMigrationsColl).
						Find(ctx, bson.M{}, findOpts)
					assert.NoError(t, err)

					err = c.All(ctx, &out)
					assert.NoError(t, err)

					if tc.automigrate {
						assert.Len(t, out, 2)
						assert.NoError(t, err)

						v, _ := migrate.NewVersion(tc.version)
						assert.Equal(t, *v, out[0].Version)
					} else {
						assert.Len(t, out, 0)
					}
				}
			}
		})
	}
}

func TestWithAutomigrate(t *testing.T) {
	db.Wipe()

	client := db.Client()

	store, err := NewDataStoreMongoWithClient(client)
	assert.NoError(t, err)

	new_store := store.WithAutomigrate()

	assert.NotEqual(t, unsafe.Pointer(store), unsafe.Pointer(new_store))
}

func TestWithMultitenant(t *testing.T) {
	db.Wipe()

	client := db.Client()

	store, err := NewDataStoreMongoWithClient(client)
	assert.NoError(t, err)

	new_store := store.WithMultitenant()

	assert.NotEqual(t, unsafe.Pointer(store), unsafe.Pointer(new_store))
}

func TestMongoDeleteToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	tokenID := oid.NewUUIDv5("id-1")

	testCases := map[string]struct {
		tenant   string
		token    *jwt.Token
		inTokens []interface{}

		outError string
	}{
		"ok": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID: tokenID,
				},
			},
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       tokenID,
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("sub-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-2",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-2",
						User:  true,
					},
				},
			},
		},
		"ok - tenant": {
			tenant: "tenant-1",
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID: tokenID,
				},
			},
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       tokenID,
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope:  "scope-1",
						Tenant: "tenantID1",
						User:   true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope:  "scope-1",
						Tenant: "tenantID1",
						User:   true,
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if len(tc.inTokens) > 0 {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					InsertMany(ctx, tc.inTokens)
				assert.NoError(t, err)
			}

			err = store.DeleteToken(ctx, tc.token.ID)
			assert.NoError(t, err)

			var tokens []jwt.Token
			c, err := client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbTokensColl).
				Find(ctx, bson.M{"_id": tc.token.ID})
			assert.NoError(t, err)

			err = c.All(ctx, &tokens)
			assert.NoError(t, err)
			assert.Nil(t, tokens)
		})
	}
}

func TestMongoDeleteTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		tenant   string
		inTokens []interface{}

		outError string
	}{
		"ok": {
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("sub-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-2",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-2",
						User:  true,
					},
				},
			},
		},
		"ok - tenant": {
			tenant: "tenant-1",
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope:  "scope-1",
						Tenant: "tenantID1",
						User:   true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("sub-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope:  "scope-1",
						Tenant: "tenantID1",
						User:   true,
					},
				},
			},
		},
		"tenant, no tokens": {
			tenant:   "tenantID2",
			outError: store.ErrTokenNotFound.Error(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if len(tc.inTokens) > 0 {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					InsertMany(ctx, tc.inTokens)
				assert.NoError(t, err)
			}

			err = store.DeleteTokens(ctx)
			if tc.outError != "" {
				assert.EqualError(t, err, tc.outError)
			} else {
				assert.NoError(t, err)
			}

			var tokens []jwt.Token
			c, err := client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbTokensColl).
				Find(ctx, bson.M{})
			assert.NoError(t, err)

			err = c.All(ctx, &tokens)

			assert.NoError(t, err)
			assert.Nil(t, tokens)
		})
	}
}

func TestMongoDeleteTokensByUserId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		tenant   string
		user     string
		inTokens []interface{}

		outTokens []jwt.Token
		outError  string
	}{
		"ok": {
			user: oid.NewUUIDv5("user-1").String(),
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
			outTokens: []jwt.Token{
				{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
		},
		"ok - tenant": {
			user:   oid.NewUUIDv5("user-1").String(),
			tenant: "tenant-1",
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
			outTokens: []jwt.Token{
				{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
		},
		"ok - no tokens": {
			user: oid.NewUUIDv5("user2").String(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if len(tc.inTokens) > 0 {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					InsertMany(ctx, tc.inTokens)
				assert.NoError(t, err)
			}

			err = store.DeleteTokensByUserId(ctx, tc.user)
			if tc.outError != "" {
				assert.EqualError(t, err, tc.outError)
			} else {
				assert.NoError(t, err)
			}

			var tokens []jwt.Token
			if tc.outTokens != nil {
				c, err := client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					Find(ctx, bson.M{})
				assert.NoError(t, err)

				err = c.All(ctx, &tokens)
				assert.NoError(t, err)
			}

			if assert.Len(t, tokens, len(tc.outTokens)) {
				for i, token := range tokens {
					assertEqualTokens(t, &tc.outTokens[i], &token)
				}
			}
		})
	}
}

func TestMongoDeleteTokensByUserIdExceptCurrentOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		tenant   string
		user     string
		inTokens []interface{}

		outTokens []jwt.Token
		outError  string
	}{
		"ok": {
			user: oid.NewUUIDv5("user-1").String(),
			inTokens: []interface{}{
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-2"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				jwt.Token{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
			outTokens: []jwt.Token{
				{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-1"),
						Subject:  oid.NewUUIDv5("user-1"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
				{
					Claims: jwt.Claims{
						ID:       oid.NewUUIDv5("id-3"),
						Subject:  oid.NewUUIDv5("user-2"),
						Audience: "audience",
						ExpiresAt: jwt.Time{
							Time: time.Now().
								Add(time.Hour),
						},
						IssuedAt: jwt.Time{
							Time: time.Now(),
						},
						Issuer: "iss-1",
						NotBefore: jwt.Time{
							Time: time.Unix(7890, 0),
						},
						Scope: "scope-1",
						User:  true,
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if len(tc.inTokens) > 0 {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					InsertMany(ctx, tc.inTokens)
				assert.NoError(t, err)
			}

			err = store.DeleteTokensByUserIdExceptCurrentOne(ctx, tc.user, tc.inTokens[0].(jwt.Token).ID)
			if tc.outError != "" {
				assert.EqualError(t, err, tc.outError)
			} else {
				assert.NoError(t, err)
			}

			var tokens []jwt.Token
			if tc.outTokens != nil {
				c, err := client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbTokensColl).
					Find(ctx, bson.M{})
				assert.NoError(t, err)

				err = c.All(ctx, &tokens)
				assert.NoError(t, err)
			}

			if assert.Len(t, tokens, len(tc.outTokens)) {
				for i, token := range tokens {
					assertEqualTokens(t, &tc.outTokens[i], &token)
				}
			}
		})
	}
}

func TestMongoSaveSettings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	// we'll preset settings _id for easy 1:1 comparison on test (normally autogenerated)
	testCases := map[string]struct {
		settingsIn       map[string]interface{}
		settingsExisting map[string]interface{}
		settingsOut      map[string]interface{}
		tenant           string
		err              string
	}{
		"ok: insert": {
			settingsIn: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": 42,
			},
			settingsOut: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": int32(42),
			},
		},
		"ok: insert, tenant": {
			settingsIn: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": 42,
			},
			settingsOut: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": int32(42),
			},
			tenant: "acme",
		},
		"ok: overwrite with exact same fields": {
			settingsIn: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": 42,
			},
			settingsExisting: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val-old",
				"bar": 0,
			},
			settingsOut: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val",
				"bar": int32(42),
			},
		},
		"ok: overwrite with different fields": {
			settingsIn: map[string]interface{}{
				"_id":  "1",
				"baz1": "baz",
				"baz2": 420,
			},
			settingsExisting: map[string]interface{}{
				"_id": "1",
				"foo": "foo-val-old",
				"bar": 0,
			},
			settingsOut: map[string]interface{}{
				"_id":  "1",
				"baz1": "baz",
				"baz2": int32(420),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if tc.settingsExisting != nil {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbSettingsColl).
					InsertOne(ctx, tc.settingsExisting)
				assert.NoError(t, err)
			}

			err = store.SaveSettings(ctx, tc.settingsIn)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}

			var settings map[string]interface{}

			err = client.
				Database(mstore.DbFromContext(ctx, DbName)).
				Collection(DbSettingsColl).
				FindOne(ctx, bson.M{}).
				Decode(&settings)

			assert.NoError(t, err)
			assert.Equal(t, tc.settingsOut, settings)
		})
	}
}

func TestMongoGetSettings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode.")
	}

	testCases := map[string]struct {
		settingsExisting map[string]interface{}
		settingsOut      map[string]interface{}
		tenant           string
		err              string
	}{
		"ok": {
			settingsExisting: map[string]interface{}{
				"foo": "foo-val",
				"bar": 42,
			},
			settingsOut: map[string]interface{}{
				"foo": "foo-val",
				"bar": int32(42),
			},
		},
		"ok, tenant": {
			settingsExisting: map[string]interface{}{
				"foo": "foo-val",
				"bar": 42,
			},
			settingsOut: map[string]interface{}{
				"foo": "foo-val",
				"bar": int32(42),
			},
			tenant: "tenant-foo",
		},
		"ok, empty": {
			settingsOut: map[string]interface{}{},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			db.Wipe()

			ctx := context.Background()
			if tc.tenant != "" {
				ctx = identity.WithContext(ctx, &identity.Identity{
					Tenant: tc.tenant,
				})
			}

			client := db.Client()
			store, err := NewDataStoreMongoWithClient(client)
			assert.NoError(t, err)

			if tc.settingsExisting != nil {
				_, err = client.
					Database(mstore.DbFromContext(ctx, DbName)).
					Collection(DbSettingsColl).
					InsertOne(ctx, tc.settingsExisting)
				assert.NoError(t, err)
			}

			out, err := store.GetSettings(ctx)

			assert.NoError(t, err)
			assert.Equal(t, tc.settingsOut, out)
		})
	}
}
