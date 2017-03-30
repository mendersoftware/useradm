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
package useradm

import (
	"context"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/useradm/jwt"
	mjwt "github.com/mendersoftware/useradm/jwt/mocks"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/scope"
	"github.com/mendersoftware/useradm/store"
	mstore "github.com/mendersoftware/useradm/store/mocks"
)

func TestUserAdmSignToken(t *testing.T) {
	//cases: handler err, no handler err
	testCases := map[string]struct {
		signed  string
		signErr error

		config Config
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

		ctx := context.Background()

		mockJWTHandler := mjwt.JWTHandler{}
		mockJWTHandler.On("ToJWT",
			mock.AnythingOfType("*jwt.Token"),
		).Return(tc.signed, tc.signErr)

		useradm := NewUserAdm(&mockJWTHandler, nil, tc.config, nil)

		sf := useradm.SignToken(ctx)

		assert.NotNil(t, sf)

		signed, err := sf(&jwt.Token{})

		if tc.signErr != nil {
			assert.EqualError(t, err, tc.signErr.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tc.signed, signed)
		}
	}

}

func TestUserAdmLogin(t *testing.T) {
	testCases := map[string]struct {
		inEmail    string
		inPassword string

		dbEmpty    bool
		dbEmptyErr error

		dbUser    *model.User
		dbUserErr error

		outErr   error
		outToken *jwt.Token

		config Config
	}{
		"ok: initial login": {
			inEmail:    "",
			inPassword: "",

			dbEmpty:    true,
			dbEmptyErr: nil,

			dbUser:    nil,
			dbUserErr: nil,

			outErr: nil,
			outToken: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "initial",
					Scope:   scope.InitialUserCreate,
				},
			},

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},

		"ok: regular login": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbEmpty:    false,
			dbEmptyErr: nil,

			dbUser: &model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			outErr: nil,
			outToken: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Scope:   scope.All,
				},
			},

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error: initial login, db IsEmpty() error": {
			dbEmptyErr: errors.New("db failed"),

			outErr: errors.New("useradm: failed to query database: db failed"),
		},
		"error: initial login, db not empty": {
			outToken: nil,
			outErr:   ErrUnauthorized,
		},
		"error: trying initial login, db not empty": {
			inEmail:    "",
			inPassword: "",

			dbEmpty:    false,
			dbEmptyErr: nil,

			dbUser:    nil,
			dbUserErr: nil,

			outErr:   ErrUnauthorized,
			outToken: nil,

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error: regular login, no user": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbEmpty:    false,
			dbEmptyErr: nil,

			dbUser:    nil,
			dbUserErr: nil,

			outErr:   ErrUnauthorized,
			outToken: nil,

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error: regular login, wrong password": {
			inEmail:    "foo@bar.com",
			inPassword: "notcorrecthorsebatterystaple",

			dbEmpty:    false,
			dbEmptyErr: nil,

			dbUser: &model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			outErr:   ErrUnauthorized,
			outToken: nil,

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error: regular login, db.GetUserByEmail() error": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbEmpty:    false,
			dbEmptyErr: nil,

			dbUser:    nil,
			dbUserErr: errors.New("db: internal error"),

			outErr:   errors.New("useradm: failed to get user: db: internal error"),
			outToken: nil,

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		ctx := context.Background()

		db := &mstore.DataStore{}
		db.On("IsEmpty", ctx).Return(tc.dbEmpty, tc.dbEmptyErr)
		db.On("GetUserByEmail", ctx, tc.inEmail).Return(tc.dbUser, tc.dbUserErr)

		useradm := NewUserAdm(nil, db, tc.config, nil)

		token, err := useradm.Login(ctx, tc.inEmail, tc.inPassword)

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
			assert.Nil(t, token)
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

func TestUserAdmCreateUser(t *testing.T) {
	testCases := map[string]struct {
		inUser model.User

		dbErr error

		outErr error
	}{
		"ok": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr:  nil,
			outErr: nil,
		},
		"db error: duplicate email": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr:  store.ErrDuplicateEmail,
			outErr: store.ErrDuplicateEmail,
		},
		"db error: general": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr: errors.New("no reachable servers"),

			outErr: errors.New("useradm: failed to create user in the db: no reachable servers"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		ctx := context.Background()

		db := &mstore.DataStore{}
		db.On("CreateUser", ctx,
			mock.AnythingOfType("*model.User")).
			Return(tc.dbErr)

		useradm := NewUserAdm(nil, db, Config{}, nil)

		err := useradm.CreateUser(ctx, &tc.inUser)

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
		}
	}

}

func TestUserAdmCreateUserInitial(t *testing.T) {
	testCases := map[string]struct {
		inUser model.User

		dbEmpty     bool
		dbEmptyErr  error
		dbCreateErr error

		outErr error
	}{
		"ok": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbEmpty:     true,
			dbEmptyErr:  nil,
			dbCreateErr: nil,
			outErr:      nil,
		},
		"error: not an initial user": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbEmpty:     false,
			dbEmptyErr:  nil,
			dbCreateErr: ErrUserNotInitial,
			outErr:      ErrUserNotInitial,
		},
		"db error: IsEmpty()": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbEmpty:     false,
			dbEmptyErr:  errors.New("no reachable servers"),
			dbCreateErr: nil,
			outErr:      errors.New("useradm: failed to check if db is empty: no reachable servers"),
		},
		"db error: CreateUser()": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbEmpty:     true,
			dbEmptyErr:  nil,
			dbCreateErr: errors.New("no reachable servers"),
			outErr:      errors.New("useradm: failed to create user in the db: no reachable servers"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		ctx := context.Background()

		db := &mstore.DataStore{}
		db.On("IsEmpty", ctx).Return(tc.dbEmpty, tc.dbEmptyErr)
		db.On("CreateUser", ctx,
			mock.AnythingOfType("*model.User")).
			Return(tc.dbCreateErr)

		useradm := NewUserAdm(nil, db, Config{}, nil)

		err := useradm.CreateUserInitial(ctx, &tc.inUser)

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestUserAdmVerify(t *testing.T) {
	testCases := map[string]struct {
		token *jwt.Token

		dbUser *model.User
		dbErr  error

		err error
	}{
		"ok": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
				},
			},
			dbUser: &model.User{
				ID: "1234",
			},
			dbErr: nil,
			err:   nil,
		},
		"error: invalid token issuer": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "foo",
				},
			},
			dbUser: nil,
			dbErr:  nil,
			err:    ErrUnauthorized,
		},
		"error: user not found": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
				},
			},
			dbUser: nil,
			err:    ErrUnauthorized,
		},
		"error: db": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
				},
			},
			dbUser: nil,
			dbErr:  errors.New("db internal error"),

			err: errors.New("useradm: failed to get user: db internal error"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		config := Config{Issuer: "mender"}

		ctx := context.Background()

		db := &mstore.DataStore{}
		db.On("GetUserById", ctx,
			tc.token.Claims.Subject).Return(tc.dbUser, tc.dbErr)

		useradm := NewUserAdm(nil, db, config, nil)

		err := useradm.Verify(ctx, tc.token)

		if tc.err != nil {
			assert.EqualError(t, err, tc.err.Error())
		} else {
			assert.NoError(t, err)
		}
	}
}
