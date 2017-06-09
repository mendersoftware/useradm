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
	"fmt"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	ct "github.com/mendersoftware/useradm/client/tenant"
	mct "github.com/mendersoftware/useradm/client/tenant/mocks"
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

		mockJWTHandler := mjwt.Handler{}
		mockJWTHandler.On("ToJWT",
			mock.AnythingOfType("*jwt.Token"),
		).Return(tc.signed, tc.signErr)

		useradm := NewUserAdm(&mockJWTHandler, nil, tc.config)
		signed, err := useradm.SignToken(ctx, &jwt.Token{})

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

		verifyTenant bool
		tenant       *ct.Tenant
		tenantErr    error

		dbUser    *model.User
		dbUserErr error

		outErr   error
		outToken *jwt.Token

		config Config
	}{
		"ok": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

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
		"ok, multitenant": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			verifyTenant: true,
			tenant: &ct.Tenant{
				ID:   "tenant1id",
				Name: "tenant1",
			},
			tenantErr: nil,

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
					Tenant:  "tenant1id",
				},
			},

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error, multitenant: tenant not found": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			verifyTenant: true,
			tenant:       nil,
			tenantErr:    nil,

			outErr:   ErrUnauthorized,
			outToken: nil,
		},
		"error, multitenant: tenant verification error": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			verifyTenant: true,
			tenant:       nil,
			tenantErr:    errors.New("some error"),

			outErr:   errors.New("failed to check user's tenant: some error"),
			outToken: nil,
		},
		"error: no user": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser:    nil,
			dbUserErr: nil,

			outErr:   ErrUnauthorized,
			outToken: nil,

			config: Config{
				Issuer:         "foobar",
				ExpirationTime: 10,
			},
		},
		"error: wrong password": {
			inEmail:    "foo@bar.com",
			inPassword: "notcorrecthorsebatterystaple",

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
		db.On("GetUserByEmail", ctx, tc.inEmail).Return(tc.dbUser, tc.dbUserErr)

		useradm := NewUserAdm(nil, db, tc.config)
		if tc.verifyTenant {
			cTenant := &mct.ClientRunner{}
			cTenant.On("GetTenant", ctx, tc.inEmail, &apiclient.HttpApi{}).
				Return(tc.tenant, tc.tenantErr)
			useradm = useradm.WithTenantVerification(cTenant)
		}

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

		useradm := NewUserAdm(nil, db, Config{})

		err := useradm.CreateUser(ctx, &tc.inUser)

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
		}
	}

}

func TestUserAdmUpdateUser(t *testing.T) {
	testCases := map[string]struct {
		inUserUpdate model.UserUpdate

		dbErr error

		outErr error
	}{
		"ok": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr:  nil,
			outErr: nil,
		},
		"db error: duplicate email": {
			inUserUpdate: model.UserUpdate{
				Email: "foo@bar.com",
			},
			dbErr:  store.ErrDuplicateEmail,
			outErr: store.ErrDuplicateEmail,
		},
		"db error: general": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr: errors.New("no reachable servers"),

			outErr: errors.New("useradm: failed to update user information: no reachable servers"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("UpdateUser", ctx,
				mock.AnythingOfType("string"),
				mock.AnythingOfType("*model.UserUpdate")).
				Return(tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			err := useradm.UpdateUser(ctx, "123", &tc.inUserUpdate)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
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

		useradm := NewUserAdm(nil, db, config)

		err := useradm.Verify(ctx, tc.token)

		if tc.err != nil {
			assert.EqualError(t, err, tc.err.Error())
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestUserAdmGetUsers(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	testCases := map[string]struct {
		dbUsers []model.User
		dbErr   error

		err error
	}{
		"ok: some users": {
			dbUsers: []model.User{
				{
					ID:        "1",
					Email:     "foo",
					CreatedTs: &ts,
				},
				{
					ID:        "2",
					Email:     "bar",
					UpdatedTs: &ts,
				},
			},
			dbErr: nil,
			err:   nil,
		},
		"ok: no users": {
			dbUsers: []model.User{},
			dbErr:   nil,
			err:     nil,
		},
		"error: db": {
			dbUsers: nil,
			dbErr:   errors.New("db connection failed"),
			err:     errors.New("useradm: failed to get users: db connection failed"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("GetUsers", ctx).Return(tc.dbUsers, tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			users, err := useradm.GetUsers(ctx)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.dbUsers, users)
			}
		})
	}
}

func TestUserAdmGetUser(t *testing.T) {
	t.Parallel()

	ts := time.Now()

	testCases := map[string]struct {
		dbUser *model.User
		dbErr  error

		err error
	}{
		"ok 1": {
			dbUser: &model.User{
				ID:        "1",
				Email:     "foo",
				UpdatedTs: &ts,
				CreatedTs: &ts,
			},
			dbErr: nil,
			err:   nil,
		},
		"ok: no user": {
			dbUser: nil,
			dbErr:  nil,
			err:    nil,
		},
		"error: generic db error": {
			dbUser: nil,
			dbErr:  errors.New("db connection failed"),
			err:    errors.New("useradm: failed to get user: db connection failed"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("GetUserById", ctx, "foo").Return(tc.dbUser, tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			user, err := useradm.GetUser(ctx, "foo")

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.dbUser, user)
			}
		})
	}
}

func TestUserAdmDeleteUser(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		dbErr error
		err   error
	}{
		"ok": {
			dbErr: nil,
			err:   nil,
		},
		"error": {
			dbErr: errors.New("db connection failed"),
			err:   errors.New("useradm: failed to delete user: db connection failed"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("DeleteUser", ctx, "foo").Return(tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			err := useradm.DeleteUser(ctx, "foo")

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
