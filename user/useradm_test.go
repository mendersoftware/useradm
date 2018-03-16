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
package useradm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/identity"
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

		useradm := NewUserAdm(&mockJWTHandler, nil, nil, tc.config)
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

		dbTokenErr error

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
		"error: db.SaveToken() error": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			dbTokenErr: errors.New("db failed"),

			outErr:   errors.New("useradm: failed to save token: db failed"),
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
		db.On("GetUserByEmail", ContextMatcher(), tc.inEmail).Return(tc.dbUser, tc.dbUserErr)

		db.On("SaveToken", ContextMatcher(), mock.AnythingOfType("*jwt.Token")).Return(tc.dbTokenErr)

		useradm := NewUserAdm(nil, db, nil, tc.config)
		if tc.verifyTenant {
			cTenant := &mct.ClientRunner{}
			cTenant.On("GetTenant", ContextMatcher(), tc.inEmail, &apiclient.HttpApi{}).
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
				assert.NotEmpty(t, token.Id)
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

		withTenantVerification bool
		propagate              bool
		tenantErr              error
		shouldVerifyTenant     bool

		dbErr error

		outErr error
	}{
		"ok": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr:              nil,
			outErr:             nil,
			propagate:          true,
			shouldVerifyTenant: false,
		},
		"ok, multitenant": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              true,
			tenantErr:              nil,
			shouldVerifyTenant:     true,

			dbErr:  nil,
			outErr: nil,
		},
		"ok, multitenant, progate: false": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              false,
			tenantErr:              nil,
			shouldVerifyTenant:     false,

			dbErr:  nil,
			outErr: nil,
		},
		"error, multitenant: duplicate user": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              true,
			tenantErr:              ct.ErrDuplicateUser,
			shouldVerifyTenant:     true,

			dbErr:  nil,
			outErr: errors.New("user with a given email already exists"),
		},
		"error, multitenant: generic": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              true,
			tenantErr:              errors.New("http 500"),
			shouldVerifyTenant:     true,

			dbErr:  nil,
			outErr: errors.New("useradm: failed to create user in tenantadm: http 500"),
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
		db.On("CreateUser",
			ContextMatcher(),
			mock.AnythingOfType("*model.User")).
			Return(tc.dbErr)

		useradm := NewUserAdm(nil, db, nil, Config{})
		cTenant := &mct.ClientRunner{}

		id := &identity.Identity{
			Tenant: "foo",
		}
		ctx = identity.WithContext(ctx, id)

		if tc.shouldVerifyTenant {
			cTenant.On("CreateUser",
				ContextMatcher(),
				mock.AnythingOfType("*tenant.User"),
				&apiclient.HttpApi{}).
				Return(tc.tenantErr)
		}
		if tc.withTenantVerification {
			useradm = useradm.WithTenantVerification(cTenant)
		}

		err := useradm.CreateUser(ctx, &tc.inUser, tc.propagate)

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
		}

		cTenant.AssertExpectations(t)
	}

}

func TestUserAdmUpdateUser(t *testing.T) {
	testCases := map[string]struct {
		inUserUpdate model.UserUpdate

		verifyTenant bool
		tenantErr    error

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
		"ok, multitenant": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			verifyTenant: true,
			tenantErr:    nil,

			dbErr:  nil,
			outErr: nil,
		},
		"error, multitenant: duplicate user": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			verifyTenant: true,
			tenantErr:    ct.ErrDuplicateUser,

			dbErr:  nil,
			outErr: errors.New("user with a given email already exists"),
		},
		"error, multitenant: not found": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			verifyTenant: true,
			tenantErr:    ct.ErrUserNotFound,

			dbErr:  nil,
			outErr: errors.New("user not found"),
		},
		"error, multitenant: generic": {
			inUserUpdate: model.UserUpdate{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			verifyTenant: true,
			tenantErr:    errors.New("http 500"),

			dbErr:  nil,
			outErr: errors.New("useradm: failed to update user in tenantadm: http 500"),
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
			db.On("UpdateUser",
				ContextMatcher(),
				mock.AnythingOfType("string"),
				mock.AnythingOfType("*model.UserUpdate")).
				Return(tc.dbErr)

			useradm := NewUserAdm(nil, db, nil, Config{})

			if tc.verifyTenant {
				id := &identity.Identity{
					Tenant: "foo",
				}
				ctx = identity.WithContext(ctx, id)

				cTenant := &mct.ClientRunner{}
				cTenant.On("UpdateUser",
					ContextMatcher(),
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					mock.AnythingOfType("*tenant.UserUpdate"),
					&apiclient.HttpApi{}).
					Return(tc.tenantErr)
				useradm = useradm.WithTenantVerification(cTenant)
			}

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

		callsDB bool
		dbUser  *model.User
		dbErr   error

		err error
	}{
		"ok": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
					User:    true,
				},
			},
			callsDB: true,
			dbUser: &model.User{
				ID: "1234",
			},
		},
		"error: invalid token issuer": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "foo",
					User:    true,
				},
			},
			err: ErrUnauthorized,
		},
		"error: not a user token": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
				},
			},
			err: ErrUnauthorized,
		},
		"error: user not found": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
					User:    true,
				},
			},
			callsDB: true,
			err:     ErrUnauthorized,
		},
		"error: db": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: "1234",
					Issuer:  "mender",
					User:    true,
				},
			},
			callsDB: true,
			dbErr:   errors.New("db internal error"),

			err: errors.New("useradm: failed to get user: db internal error"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("test case: %s", name), func(t *testing.T) {

			config := Config{Issuer: "mender"}

			ctx := context.Background()

			db := &mstore.DataStore{}
			if tc.callsDB || tc.dbUser != nil || tc.dbErr != nil {
				db.On("GetUserById", ctx,
					tc.token.Claims.Subject).Return(tc.dbUser, tc.dbErr)
			}

			useradm := NewUserAdm(nil, db, nil, config)

			err := useradm.Verify(ctx, tc.token)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
			db.AssertExpectations(t)
		})
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

			useradm := NewUserAdm(nil, db, nil, Config{})

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

			useradm := NewUserAdm(nil, db, nil, Config{})

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
		verifyTenant bool
		tenantErr    error
		dbErr        error
		err          error
	}{
		"ok": {
			dbErr: nil,
			err:   nil,
		},
		"ok, multitenant": {
			verifyTenant: true,
			dbErr:        nil,
			err:          nil,
		},
		"multitenant, tenantadm error": {
			verifyTenant: true,
			tenantErr:    errors.New("http 500"),
			dbErr:        nil,
			err:          errors.New("useradm: failed to delete user in tenantadm: http 500"),
		},
		"error": {
			dbErr: errors.New("db connection failed"),
			err:   errors.New("useradm: failed to delete user: db connection failed"),
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("DeleteUser", ContextMatcher(), "foo").Return(tc.dbErr)

			useradm := NewUserAdm(nil, db, nil, Config{})
			if tc.verifyTenant {
				id := &identity.Identity{
					Tenant: "bar",
				}
				ctx = identity.WithContext(ctx, id)

				cTenant := &mct.ClientRunner{}
				cTenant.On("DeleteUser",
					ContextMatcher(),
					"bar", "foo",
					&apiclient.HttpApi{}).
					Return(tc.tenantErr)
				useradm = useradm.WithTenantVerification(cTenant)
			}

			err := useradm.DeleteUser(ctx, "foo")

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserAdmCreateTenant(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tenant    string
		tenantErr error
		err       error
	}{
		"ok": {
			tenant: "foobar",
		},
		"error": {
			tenant:    "1234",
			tenantErr: errors.New("migration failed"),
			err:       errors.New("failed to apply migrations for tenant 1234: migration failed"),
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			tenantDb := &mstore.TenantDataKeeper{}
			tenantDb.On("MigrateTenant", ContextMatcher(), tc.tenant).Return(tc.tenantErr)

			useradm := NewUserAdm(nil, nil, tenantDb, Config{})

			err := useradm.CreateTenant(ctx, model.NewTenant{ID: tc.tenant})
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserAdmSetPassword(t *testing.T) {
	testCases := map[string]struct {
		inUser      model.User
		dbGetErr    error
		dbUpdateErr error
		outErr      error
		foundUser   *model.User
	}{
		"ok": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbGetErr:  nil,
			outErr:    nil,
			foundUser: &model.User{ID: "test_id"},
		},

		"error, user not found": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			dbGetErr:  nil,
			outErr:    errors.New("user not found"),
			foundUser: nil,
		},

		"error, get from db": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			dbGetErr:  errors.New("db failed"),
			outErr:    errors.New("useradm: failed to get user by email: db failed"),
			foundUser: nil,
		},
		"error, update db": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			dbUpdateErr: errors.New("db failed"),
			outErr:      errors.New("useradm: failed to update user information: db failed"),
			foundUser:   &model.User{ID: "test_id"},
		},
	}
	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		ctx := context.Background()

		db := &mstore.DataStore{}

		db.On("GetUserByEmail",
			ContextMatcher(),
			tc.inUser.Email).
			Return(tc.foundUser, tc.dbGetErr)

		if tc.foundUser != nil {
			db.On("UpdateUser",
				ContextMatcher(),
				tc.foundUser.ID,
				mock.AnythingOfType("*model.UserUpdate")).
				Return(tc.dbUpdateErr)
		}
		useradm := NewUserAdm(nil, db, nil, Config{})
		cTenant := &mct.ClientRunner{}

		err := useradm.SetPassword(ctx, model.UserUpdate{Email: tc.inUser.Email})

		if tc.outErr != nil {
			assert.EqualError(t, err, tc.outErr.Error())
		} else {
			assert.NoError(t, err)
		}

		cTenant.AssertExpectations(t)
	}

}

func ContextMatcher() interface{} {
	return mock.MatchedBy(func(c context.Context) bool {
		return true
	})
}
