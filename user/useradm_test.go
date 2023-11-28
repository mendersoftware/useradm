// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package useradm

import (
	"context"
	"github.com/mendersoftware/useradm/common"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"

	"github.com/mendersoftware/useradm/client/tenant"
	ct "github.com/mendersoftware/useradm/client/tenant"
	mct "github.com/mendersoftware/useradm/client/tenant/mocks"
	"github.com/mendersoftware/useradm/jwt"
	mjwt "github.com/mendersoftware/useradm/jwt/mocks"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/scope"
	"github.com/mendersoftware/useradm/store"
	mstore "github.com/mendersoftware/useradm/store/mocks"
)

func TestHealthCheck(t *testing.T) {
	testCases := []struct {
		Name string

		MultiTenant    bool
		DataStoreError error
		TenantAdmError error
	}{{
		Name: "ok",
	}, {
		Name:        "ok, multitenant",
		MultiTenant: true,
	}, {
		Name:           "error, datastore unhealthy",
		DataStoreError: errors.New("connection refused"),
	}, {
		Name:           "error, tenantadm unhealthy",
		MultiTenant:    true,
		TenantAdmError: errors.New("connection refused"),
	}}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(
				context.Background(), time.Second*5,
			)
			defer cancel()
			db := &mstore.DataStore{}
			db.On("Ping", ctx).Return(tc.DataStoreError)
			useradm := NewUserAdm(nil, db, Config{})
			if tc.MultiTenant {
				cTenant := &mct.ClientRunner{}
				cTenant.On("CheckHealth", ctx).
					Return(tc.TenantAdmError)
				useradm = useradm.WithTenantVerification(cTenant)
			}
			err := useradm.HealthCheck(ctx)
			switch {
			case tc.DataStoreError != nil:
				assert.EqualError(t, err,
					"error reaching MongoDB: "+
						tc.DataStoreError.Error(),
				)
			case tc.TenantAdmError != nil && tc.MultiTenant:
				assert.EqualError(t, err,
					"Tenantadm service unhealthy: "+
						tc.TenantAdmError.Error(),
				)
			default:
				assert.NoError(t, err)
			}
		})
	}
}

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
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			mockJWTHandler := mjwt.Handler{}
			mockJWTHandler.On("ToJWT",
				mock.AnythingOfType("*jwt.Token"),
			).Return(tc.signed, tc.signErr)

			useradm := NewUserAdm(map[int]jwt.Handler{0: &mockJWTHandler}, nil, tc.config)
			signed, err := useradm.SignToken(ctx, &jwt.Token{})

			if tc.signErr != nil {
				assert.EqualError(t, err, tc.signErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.signed, signed)
			}
		})
	}

}

func TestUserAdmLogin(t *testing.T) {
	const sessionTokensLimit = 10

	testCases := map[string]struct {
		inEmail    model.Email
		inPassword string
		noExpiry   bool

		verifyTenant bool
		tenant       *ct.Tenant
		tenantErr    error

		dbUser    *model.User
		dbUserErr error

		dbTokenErr        error
		dbEnsureLimitsErr error
		dbUpdateErr       error

		outErr   error
		outToken *jwt.Token

		config Config
	}{
		"ok": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			outErr: nil,
			outToken: &jwt.Token{
				Claims: jwt.Claims{
					Subject: oid.NewUUIDv5("1234"),
					Scope:   scope.All,
				},
			},

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
			},
		},
		"ok, multitenant": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			verifyTenant: true,
			tenant: &ct.Tenant{
				ID:   "TenantID1",
				Name: "tenant1",
			},
			tenantErr: nil,

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,
			// error for updating login_ts is suppressed
			dbUpdateErr: errors.New("internal error"),

			outErr: nil,
			outToken: &jwt.Token{
				Claims: jwt.Claims{
					Subject: oid.NewUUIDv5("1234"),
					Scope:   scope.All,
					Tenant:  "TenantID1",
				},
			},

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
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
		"error, multitenant: tenant account suspended": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			verifyTenant: true,
			tenant: &ct.Tenant{
				ID:     "TenantID1",
				Name:   "tenant1",
				Status: "suspended",
			},
			tenantErr: nil,

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			outErr: ErrTenantAccountSuspended,

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
			},
		},
		"error: no user": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser:    nil,
			dbUserErr: nil,

			outErr:   ErrUnauthorized,
			outToken: nil,

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
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
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
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
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
			},
		},
		"error: db.SaveToken() error": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			dbTokenErr: errors.New("db failed"),

			outErr:   errors.New("useradm: failed to save token: db failed"),
			outToken: nil,

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
			},
		},
		"error: db.EnsureSessionTokensLimit() error": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			dbUserErr: nil,

			dbEnsureLimitsErr: errors.New("db failed"),

			outErr:   errors.New("useradm: failed to ensure session tokens limit: db failed"),
			outToken: nil,

			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitSessionsPerUser:  sessionTokensLimit,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("GetUserByEmail", ContextMatcher(), tc.inEmail).Return(tc.dbUser, tc.dbUserErr)

			db.On("SaveToken", ContextMatcher(), mock.AnythingOfType("*jwt.Token")).Return(tc.dbTokenErr)
			if tc.dbTokenErr == nil {
				db.On("EnsureSessionTokensLimit", ContextMatcher(), mock.AnythingOfType("oid.ObjectID"),
					sessionTokensLimit).Return(tc.dbEnsureLimitsErr)
			}
			if tc.dbUser != nil {
				db.On("UpdateLoginTs", ContextMatcher(), tc.dbUser.ID).
					Return(tc.dbUpdateErr)
			}

			useradm := NewUserAdm(nil, db, tc.config)
			if tc.verifyTenant {
				cTenant := &mct.ClientRunner{}
				cTenant.On("GetTenant", ContextMatcher(), string(tc.inEmail), &apiclient.HttpApi{}).
					Return(tc.tenant, tc.tenantErr)
				useradm = useradm.WithTenantVerification(cTenant)
			}

			token, err := useradm.Login(ctx, tc.inEmail, tc.inPassword, &LoginOptions{
				NoExpiry: tc.noExpiry,
			})

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
				assert.Nil(t, token)
			} else {
				if tc.outToken != nil && assert.NotNil(t, token) {
					assert.NoError(t, err)
					assert.NotEmpty(t, token.ID)
					assert.NotEmpty(t, token.Claims.ID)
					assert.Equal(t, tc.config.Issuer, token.Claims.Issuer)
					assert.Equal(t, tc.outToken.Claims.Scope, token.Claims.Scope)
					assert.WithinDuration(t,
						time.Now().Add(time.Duration(tc.config.ExpirationTimeSeconds)*time.Second),
						token.Claims.ExpiresAt.Time,
						time.Second)

				}
			}
		})
	}

}

func TestUserAdmLogout(t *testing.T) {
	testCases := map[string]struct {
		token            *jwt.Token
		deleteTokenError error

		err error
	}{
		"ok": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: oid.NewUUIDv5("1234"),
					Scope:   scope.All,
				},
			},
		},
		"ko": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					Subject: oid.NewUUIDv5("1234"),
					Scope:   scope.All,
				},
			},
			deleteTokenError: errors.New("error"),
			err:              errors.New("error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On(
				"DeleteToken",
				ContextMatcher(),
				tc.token.Subject,
				tc.token.ID,
			).Return(tc.deleteTokenError)
			defer db.AssertExpectations(t)

			useradm := NewUserAdm(nil, db, Config{})
			err := useradm.Logout(ctx, tc.token)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestUserAdmDoCreateUser(t *testing.T) {
	testCases := map[string]struct {
		inUser model.User

		withTenantVerification     bool
		propagate                  bool
		tenantCreateUserErr        error
		tenantDeleteUserErr        error
		shouldVerifyTenant         bool
		shouldCompensateTenantUser bool

		dbUser       *model.User
		dbGetUserErr error

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
			tenantCreateUserErr:    nil,
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
			tenantCreateUserErr:    nil,
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
			tenantCreateUserErr:    ct.ErrDuplicateUser,
			shouldVerifyTenant:     true,
			dbUser: &model.User{
				ID:       "1234",
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},

			dbErr:  nil,
			outErr: errors.New("user with a given email already exists"),
		},
		"error, multitenant: duplicate user, no user in useradm": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification:     true,
			propagate:                  true,
			tenantCreateUserErr:        ct.ErrDuplicateUser,
			shouldVerifyTenant:         true,
			shouldCompensateTenantUser: true,

			dbErr:  nil,
			outErr: errors.New("tenant data out of sync: user with the same name already exists"),
		},
		"error, multitenant: duplicate user, no user in useradm, compensate error": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification:     true,
			propagate:                  true,
			tenantCreateUserErr:        ct.ErrDuplicateUser,
			tenantDeleteUserErr:        errors.New("delate user error"),
			shouldVerifyTenant:         true,
			shouldCompensateTenantUser: true,

			dbErr:  nil,
			outErr: errors.New("tenant data out of sync: faield to delete tenant user: delate user error"),
		},
		"error, multitenant: duplicate user, get user error": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              true,
			shouldVerifyTenant:     true,
			tenantCreateUserErr:    ct.ErrDuplicateUser,

			dbGetUserErr: errors.New("db error"),
			dbErr:        nil,
			outErr:       errors.New("tenant data out of sync: failed to get user from db: db error"),
		},
		"error, multitenant: generic": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},

			withTenantVerification: true,
			propagate:              true,
			tenantCreateUserErr:    errors.New("http 500"),
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
		"db error, multitenant: duplicate email": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			withTenantVerification: true,
			propagate:              true,
			shouldVerifyTenant:     true,
			dbErr:                  store.ErrDuplicateEmail,
			outErr:                 store.ErrDuplicateEmail,
		},
		"db error: general": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			dbErr: errors.New("no reachable servers"),

			outErr: errors.New("useradm: failed to create user in the db: no reachable servers"),
		},
		"db error, multitenant: general": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			withTenantVerification:     true,
			propagate:                  true,
			shouldVerifyTenant:         true,
			shouldCompensateTenantUser: true,

			dbErr:  errors.New("no reachable servers"),
			outErr: errors.New("useradm: failed to create user in the db: no reachable servers"),
		},
		"db error, multitenant: general, compensate error": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			withTenantVerification:     true,
			propagate:                  true,
			shouldVerifyTenant:         true,
			shouldCompensateTenantUser: true,
			tenantDeleteUserErr:        errors.New("delate user error"),

			dbErr:  errors.New("no reachable servers"),
			outErr: errors.New("useradm: failed to create user in the db: faield to delete tenant user: delate user error: no reachable servers"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("CreateUser",
				ContextMatcher(),
				mock.AnythingOfType("*model.User")).
				Return(tc.dbErr)

			db.On("GetUserByEmail", ContextMatcher(), mock.AnythingOfType("model.Email")).
				Return(tc.dbUser, tc.dbGetUserErr)

			useradm := NewUserAdm(nil, db, Config{})
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
					Return(tc.tenantCreateUserErr)

				if tc.shouldCompensateTenantUser {
					cTenant.On("DeleteUser",
						ContextMatcher(),
						mock.AnythingOfType("string"), mock.AnythingOfType("string"),
						&apiclient.HttpApi{}).
						Return(tc.tenantDeleteUserErr)
				}
			}
			if tc.withTenantVerification {
				useradm = useradm.WithTenantVerification(cTenant)
			}

			err := useradm.doCreateUser(ctx, &tc.inUser, tc.propagate)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}

			cTenant.AssertExpectations(t)
		})
	}

}

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func TestUserAdmUpdateUser(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		inUserUpdate   model.UserUpdate
		getUserById    *model.User
		getUserByIdErr error

		verifyTenant bool
		tenantErr    error

		dbErr error

		outErr error
	}{
		"ok": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			dbErr:  nil,
			outErr: nil,
		},
		"ok email with current token": {
			inUserUpdate: model.UserUpdate{
				Email:           "foofoo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
				Token:           &jwt.Token{Claims: jwt.Claims{ID: oid.NewUUIDv5("token-1")}},
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			dbErr:  nil,
			outErr: nil,
		},
		"ok with current token": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
				Token:           &jwt.Token{Claims: jwt.Claims{ID: oid.NewUUIDv5("token-1")}},
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			verifyTenant: true,
			tenantErr:    nil,

			dbErr:  nil,
			outErr: nil,
		},
		"ok, multitenant": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			verifyTenant: true,
			tenantErr:    nil,

			dbErr:  nil,
			outErr: nil,
		},
		"error, multitenant: duplicate user": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			verifyTenant: true,
			tenantErr:    ct.ErrDuplicateUser,

			dbErr:  nil,
			outErr: errors.New("user with a given email already exists"),
		},
		"error, multitenant: not found": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			verifyTenant: true,
			tenantErr:    ct.ErrUserNotFound,

			dbErr:  nil,
			outErr: errors.New("user not found"),
		},
		"error, multitenant: generic": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			verifyTenant: true,
			tenantErr:    errors.New("http 500"),

			dbErr:  nil,
			outErr: errors.New("useradm: failed to update user in tenantadm: http 500"),
		},
		"db error: duplicate email": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Email:    "foo@bar.com",
				Password: hashPassword("current"),
			},

			dbErr:  store.ErrDuplicateEmail,
			outErr: store.ErrDuplicateEmail,
		},
		"db error: general": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			dbErr:  errors.New("no reachable servers"),
			outErr: errors.New("useradm: failed to update user information: no reachable servers"),
		},
		"error: getUserById": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},
			getUserByIdErr: errors.New("error"),

			dbErr:  nil,
			outErr: errors.New("useradm: failed to get user: error"),
		},
		"error: getUserById not found": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "current",
			},

			dbErr:  nil,
			outErr: store.ErrUserNotFound,
		},
		"error: password mismatch": {
			inUserUpdate: model.UserUpdate{
				Email:           "foo@bar.com",
				Password:        "correcthorsebatterystaple",
				CurrentPassword: "wrong",
			},
			getUserById: &model.User{
				Password: hashPassword("current"),
			},

			dbErr:  nil,
			outErr: ErrCurrentPasswordMismatch,
		},
		"error: email without current password": {
			inUserUpdate: model.UserUpdate{
				Email: "foobar@bar.com",
			},
			getUserById: &model.User{
				Email:    "foo@bar.com",
				Password: hashPassword("current"),
			},

			dbErr:  nil,
			outErr: ErrCurrentPasswordMismatch,
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			const userID = "8258b2c3-38c2-4ffd-97c6-19e43f1ea2cf"

			ctx := identity.WithContext(context.Background(), &identity.Identity{Subject: userID})

			db := &mstore.DataStore{}
			defer db.AssertExpectations(t)

			db.On("GetUserAndPasswordById",
				ContextMatcher(),
				mock.AnythingOfType("string"),
			).Return(tc.getUserById, tc.getUserByIdErr)

			if tc.getUserByIdErr == nil && tc.outErr != ErrCurrentPasswordMismatch &&
				(len(tc.inUserUpdate.Password) == 0 || tc.getUserById != nil) &&
				(!tc.verifyTenant || tc.tenantErr == nil) {
				db.On("UpdateUser",
					ContextMatcher(),
					userID,
					mock.AnythingOfType("*model.UserUpdate")).
					Return(&model.User{
						Email:    tc.inUserUpdate.Email,
						Password: tc.inUserUpdate.Password,
					}, tc.dbErr)

				if tc.dbErr == nil && tc.inUserUpdate.Token == nil {
					db.On("DeleteTokensByUserId",
						ContextMatcher(),
						mock.AnythingOfType("string"),
					).Return(nil)
				} else if tc.dbErr == nil {
					db.On("DeleteTokensByUserIdExceptCurrentOne",
						ContextMatcher(),
						mock.AnythingOfType("string"),
						tc.inUserUpdate.Token.ID,
					).Return(nil)
				}
			}

			useradm := NewUserAdm(nil, db, Config{})

			if tc.verifyTenant {
				id := &identity.Identity{
					Tenant:  "foo",
					Subject: userID,
				}
				ctx = identity.WithContext(ctx, id)

				cTenant := &mct.ClientRunner{}
				defer cTenant.AssertExpectations(t)

				cTenant.On("UpdateUser",
					ContextMatcher(),
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					mock.AnythingOfType("*tenant.UserUpdate"),
					&apiclient.HttpApi{}).
					Return(tc.tenantErr)
				useradm = useradm.WithTenantVerification(cTenant)
			}

			err := useradm.UpdateUser(ctx, userID, &tc.inUserUpdate)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}

	etagPtr := func(etag model.ETag) *model.ETag { return &etag }
	type testCase struct {
		Name string

		CTX        context.Context
		ID         string
		UserUpdate *model.UserUpdate

		DataStore       func(t *testing.T, self *testCase) *mstore.DataStore
		TenantadmClient func(t *testing.T, self *testCase) *mct.ClientRunner

		Error error
	}
	tcs := []testCase{{
		Name: "changing password of other user not allowed",

		CTX: identity.WithContext(context.Background(), &identity.Identity{
			Tenant:  "000000000000000000000000",
			Subject: "36481319-7986-4bd9-9621-f143fc42bcca",
		}),
		ID: "0db11a0e-afac-4d73-aa6b-ccd857019553",
		UserUpdate: &model.UserUpdate{
			Password: "foobar",
			ETag:     etagPtr(model.ETag{0}),
		},
		DataStore: func(t *testing.T, self *testCase) *mstore.DataStore {
			ds := new(mstore.DataStore)
			ds.On("GetUserAndPasswordById", self.CTX, self.ID).
				Return(&model.User{ID: self.ID, ETag: &model.ETag{0}}, nil)
			return ds
		},
		Error: ErrCannotModifyPassword,
	}, {
		Name: "entity tag mismatch/on user lookup",

		CTX: identity.WithContext(context.Background(), &identity.Identity{
			Tenant:  "000000000000000000000000",
			Subject: "36481319-7986-4bd9-9621-f143fc42bcca",
		}),
		ID: "0db11a0e-afac-4d73-aa6b-ccd857019553",
		UserUpdate: &model.UserUpdate{
			Email: model.Email("test@mender.io"),
			ETag:  etagPtr(model.ETag{0}),
		},
		DataStore: func(t *testing.T, self *testCase) *mstore.DataStore {
			ds := new(mstore.DataStore)
			ds.On("GetUserAndPasswordById", self.CTX, self.ID).
				Return(&model.User{ID: self.ID, ETag: &model.ETag{1}}, nil)
			return ds
		},
		Error: ErrETagMismatch,
	}, {
		Name: "entity tag mismatch/on user update",

		CTX: identity.WithContext(context.Background(), &identity.Identity{
			Tenant:  "000000000000000000000000",
			Subject: "36481319-7986-4bd9-9621-f143fc42bcca",
		}),
		ID: "0db11a0e-afac-4d73-aa6b-ccd857019553",
		UserUpdate: &model.UserUpdate{
			Email: model.Email("test@mender.io"),
			ETag:  etagPtr(model.ETag{0}),
		},
		DataStore: func(t *testing.T, self *testCase) *mstore.DataStore {
			ds := new(mstore.DataStore)
			ds.On("GetUserAndPasswordById", self.CTX, self.ID).
				Return(&model.User{ID: self.ID, ETag: &model.ETag{0}}, nil).
				On("UpdateUser", self.CTX, self.ID, self.UserUpdate).
				Return(nil, store.ErrUserNotFound)

			return ds
		},
		TenantadmClient: func(t *testing.T, self *testCase) *mct.ClientRunner {
			tnc := new(mct.ClientRunner)
			tnc.On("UpdateUser",
				self.CTX,
				"000000000000000000000000",
				self.ID,
				&tenant.UserUpdate{
					Name: string(self.UserUpdate.Email),
				},
				mock.AnythingOfType("*http.Client")).
				Return(nil)
			return tnc
		},
		Error: ErrETagMismatch,
	}}
	for i := range tcs {
		tc := tcs[i]
		t.Run(tc.Name, func(t *testing.T) {
			var (
				ds  *mstore.DataStore
				tnc *mct.ClientRunner
			)
			if tc.DataStore != nil {
				ds = tc.DataStore(t, &tc)
			} else {
				ds = new(mstore.DataStore)
			}
			defer ds.AssertExpectations(t)
			if tc.TenantadmClient != nil {
				tnc = tc.TenantadmClient(t, &tc)
			} else {
				tnc = new(mct.ClientRunner)
			}
			defer tnc.AssertExpectations(t)

			app := UserAdm{
				verifyTenant: true,
				cTenant:      tnc,
				db:           ds,
				clientGetter: func() apiclient.HttpRunner {
					return new(http.Client)
				},
			}

			err := app.UpdateUser(tc.CTX, tc.ID, tc.UserUpdate)
			if tc.Error != nil {
				assert.ErrorIs(t, err, tc.Error)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserAdmVerify(t *testing.T) {
	testCases := map[string]struct {
		token *jwt.Token

		dbUser    *model.User
		dbUserErr error

		dbToken    *jwt.Token
		dbTokenErr error

		err error
	}{
		"ok": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
			dbUser: &model.User{
				ID: oid.NewUUIDv5("1234").String(),
			},
			dbToken: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
		},
		"error: invalid token issuer": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "foo",
					User:    true,
				},
			},
			err: ErrUnauthorized,
		},
		"error: not a user token": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
				},
			},
			err: ErrUnauthorized,
		},
		"error: user not found": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
			err: ErrUnauthorized,
		},
		"error: token not found": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
			dbUser: &model.User{
				ID: oid.NewUUIDv5("1234").String(),
			},

			dbToken:    nil,
			dbTokenErr: nil,

			err: ErrUnauthorized,
		},
		"error: db user": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
			dbUserErr: errors.New("db internal error"),

			err: errors.New("useradm: failed to get user: db internal error"),
		},
		"error: db token": {
			token: &jwt.Token{
				Claims: jwt.Claims{
					ID:      oid.NewUUIDv5("token-1"),
					Subject: oid.NewUUIDv5("1234"),
					Issuer:  "mender",
					User:    true,
				},
			},
			dbUser: &model.User{
				ID: "1234",
			},

			dbToken:    nil,
			dbTokenErr: errors.New("db failed"),

			err: errors.New("useradm: failed to get token: db failed"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			config := Config{Issuer: "mender"}

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("GetUserById", ctx,
				tc.token.Claims.Subject.String()).
				Return(tc.dbUser, tc.dbUserErr)
			db.On("GetTokenById", ctx, tc.token.ID).
				Return(tc.dbToken, tc.dbTokenErr)

			useradm := NewUserAdm(nil, db, config)

			err := useradm.Verify(ctx, tc.token)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
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
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("GetUsers", ctx, model.UserFilter{}).
				Return(tc.dbUsers, tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			users, err := useradm.GetUsers(ctx, model.UserFilter{})

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
		t.Run(name, func(t *testing.T) {

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
		verifyTenant      bool
		tenantErr         error
		dbDeleteUserErr   error
		dbDeleteTokensErr error
		err               error
	}{
		"ok": {
			err: nil,
		},
		"ok, multitenant": {
			verifyTenant: true,
			err:          nil,
		},
		"multitenant, tenantadm error": {
			verifyTenant: true,
			tenantErr:    errors.New("http 500"),
			err:          errors.New("useradm: failed to delete user in tenantadm: http 500"),
		},
		"error deleting user": {
			dbDeleteUserErr: errors.New("db connection failed"),
			err:             errors.New("useradm: failed to delete user: db connection failed"),
		},
		"error deleting user tokens": {
			dbDeleteTokensErr: errors.New("db connection failed"),
			err:               errors.New("useradm: failed to delete user tokens: db connection failed"),
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("DeleteUser", ContextMatcher(), "foo").Return(tc.dbDeleteUserErr)
			db.On("DeleteTokensByUserId", ContextMatcher(), "foo").Return(tc.dbDeleteTokensErr)

			useradm := NewUserAdm(nil, db, Config{})
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
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			useradm := NewUserAdm(nil, nil, Config{})

			err := useradm.CreateTenant(ctx, model.NewTenant{ID: tc.tenant})
			assert.NoError(t, err)
		})
	}
}

func TestUserAdmSetPassword(t *testing.T) {
	testCases := map[string]struct {
		inUser       model.User
		currentToken *jwt.Token
		dbGetErr     error
		dbUpdateErr  error
		outErr       error
		foundUser    *model.User
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

		"ok with current token": {
			inUser: model.User{
				Email:    "foo@bar.com",
				Password: "correcthorsebatterystaple",
			},
			currentToken: &jwt.Token{Claims: jwt.Claims{ID: oid.NewUUIDv5("token-1")}},
			dbGetErr:     nil,
			outErr:       nil,
			foundUser:    &model.User{ID: "test_id"},
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
		t.Run(name, func(t *testing.T) {
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
					Return(&tc.inUser, tc.dbUpdateErr)
			}

			if tc.foundUser != nil && tc.dbUpdateErr == nil {
				if tc.currentToken == nil {
					db.On("DeleteTokensByUserId",
						ContextMatcher(),
						mock.AnythingOfType("string"),
					).Return(nil)
				} else {
					db.On("DeleteTokensByUserIdExceptCurrentOne",
						ContextMatcher(),
						mock.AnythingOfType("string"),
						tc.currentToken.ID,
					).Return(nil)
				}
			}

			useradm := NewUserAdm(nil, db, Config{})
			cTenant := &mct.ClientRunner{}

			err := useradm.SetPassword(ctx, model.UserUpdate{Email: tc.inUser.Email, Password: "new-password", Token: tc.currentToken})

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}

			cTenant.AssertExpectations(t)
			db.AssertExpectations(t)
		})
	}

}

func ContextMatcher() interface{} {
	return mock.MatchedBy(func(c context.Context) bool {
		return true
	})
}

func TestUserAdmDeleteTokens(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		user   string
		tenant string
		dbErr  error

		outErr error
	}{
		"ok": {},
		"ok, tenant": {
			tenant: "foo",
		},
		"ok, tenant and user": {
			tenant: "foo",
			user:   "foo",
		},
		"db error": {
			user:   "foo",
			tenant: "foo",
			dbErr:  errors.New("db connection failed"),
			outErr: errors.New("failed to delete tokens for tenant: foo, user id: foo: db connection failed"),
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			db := &mstore.DataStore{}
			db.On("DeleteTokens", ContextMatcher(), mock.AnythingOfType("string")).Return(tc.dbErr)
			db.On("DeleteTokensByUserId", ContextMatcher(), mock.AnythingOfType("string")).Return(tc.dbErr)

			useradm := NewUserAdm(nil, db, Config{})

			err := useradm.DeleteTokens(ctx, tc.tenant, tc.user)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func TestUserAdmIssuePersonalAccessToken(t *testing.T) {
	testCases := map[string]struct {
		tokenRequest model.TokenRequest

		callDbSaveToken   bool
		dbSaveTokenErr    error
		callDbCountTokens bool
		dbCountTokens     int64
		dbCountTokensErr  error

		config Config

		outErr error
	}{
		"ok": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbSaveToken:   true,
			callDbCountTokens: true,
			dbCountTokens:     9,
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitTokensPerUser:    10,
			},
		},
		"ok, no limit": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbSaveToken: true,
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
			},
		},
		"error: too many tokens": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbCountTokens: true,
			dbCountTokens:     10,
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitTokensPerUser:    10,
			},
			outErr: ErrTooManyTokens,
		},
		"error: count tokens error": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbCountTokens: true,
			dbCountTokens:     0,
			dbCountTokensErr:  errors.New("count tokens error"),
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitTokensPerUser:    10,
			},
			outErr: errors.New(
				"useradm: failed to count personal access tokens: count tokens error"),
		},
		"error: duplicate token name": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbSaveToken:   true,
			dbSaveTokenErr:    store.ErrDuplicateTokenName,
			callDbCountTokens: true,
			dbCountTokens:     9,
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitTokensPerUser:    10,
			},
			outErr: ErrDuplicateTokenName,
		},
		"error: save token error": {
			tokenRequest: model.TokenRequest{
				Name:      stringPtr("foo"),
				ExpiresIn: 3600,
			},
			callDbSaveToken:   true,
			dbSaveTokenErr:    errors.New("save token error"),
			callDbCountTokens: true,
			dbCountTokens:     9,
			config: Config{
				Issuer:                "foobar",
				ExpirationTimeSeconds: 10,
				LimitTokensPerUser:    10,
			},
			outErr: errors.New("useradm: failed to save token: save token error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			db := &mstore.DataStore{}
			defer db.AssertExpectations(t)
			if tc.callDbSaveToken {
				db.On("SaveToken",
					ContextMatcher(),
					mock.AnythingOfType("*jwt.Token")).
					Return(tc.dbSaveTokenErr)
			}
			if tc.callDbCountTokens {
				db.On("CountPersonalAccessTokens",
					ContextMatcher(),
					"foo").
					Return(tc.dbCountTokens, tc.dbCountTokensErr)
			}

			mockJWTHandler := mjwt.Handler{}
			mockJWTHandler.On("ToJWT",
				mock.AnythingOfType("*jwt.Token"),
			).Return("signed", nil)

			useradm := NewUserAdm(map[int]jwt.Handler{0: &mockJWTHandler}, db, tc.config)

			id := &identity.Identity{
				Subject: "foo",
				Tenant:  "bar",
			}
			ctx = identity.WithContext(ctx, id)

			_, err := useradm.IssuePersonalAccessToken(ctx, &tc.tokenRequest)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}

}

func TestUserAdmGetPlans(t *testing.T) {
	t.Parallel()

	planList := []model.Plan{
		{
			Name: "plan1",
		},
		{
			Name: "plan2",
		},
		{
			Name: "plan3",
		},
		{
			Name: "plan4",
		},
		{
			Name: "plan5",
		},
		{
			Name: "plan6",
		},
		{
			Name: "plan7",
		},
		{
			Name: "plan8",
		},
		{
			Name: "plan9",
		},
		{
			Name: "plan10",
		},
	}

	testCases := map[string]struct {
		skip  int
		limit int
		plans []model.Plan
	}{
		"ok, empty": {
			skip:  0,
			limit: 0,
			plans: []model.Plan{},
		},
		"ok": {
			skip:  0,
			limit: 10,
			plans: planList,
		},
		"ok 1": {
			skip:  3,
			limit: 4,
			plans: planList[3:7],
		},
		"ok 2": {
			skip:  7,
			limit: 10,
			plans: planList[7:],
		},
		"ok 3": {
			skip:  20,
			limit: 10,
			plans: []model.Plan{},
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			useradm := NewUserAdm(nil, nil, Config{})

			model.PlanList = planList
			plans := useradm.GetPlans(ctx, tc.skip, tc.limit)

			assert.Equal(t, plans, tc.plans)
		})
	}
}

func TestUserAdmGetPlanBinding(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		plans       []model.Plan
		planBinding *model.PlanBindingDetails
	}{
		"ok": {
			plans: []model.Plan{
				{
					Name: "plan1",
				},
			},
			planBinding: &model.PlanBindingDetails{
				Plan: model.Plan{
					Name: "plan1",
				},
			},
		},
		"ok, no plans": {
			planBinding: &model.PlanBindingDetails{},
		},
	}

	for name := range testCases {
		tc := testCases[name]
		t.Run(name, func(t *testing.T) {

			t.Logf("test case: %s", name)

			ctx := context.Background()

			useradm := NewUserAdm(nil, nil, Config{})
			model.PlanList = tc.plans

			pB, err := useradm.GetPlanBinding(ctx)
			assert.NoError(t, err)
			assert.Equal(t, pB, tc.planBinding)
		})
	}
}

var (
	// tokens* maps hold tokens gined by keys of given id and carrying kid, KeyIdZero, or no kid respectively
	tokensEdKeyNoKid = map[int]string{
		22899: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzYmM3NGQwZC02YjhhLTQ3OWMtOTViOS1iMGY2YTFiOWY0YWYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1MTksImlhdCI6MTcwMTE3MzcxOSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzE5fQ.3VNlSrIAhvFImp8rQ-fS8R22pMeOwbGPmGYiuw7Qir_oQl9klzIVUVu07wa4zUu72sUDNfKkRbbiJtJhbZx2AQ",
		14211: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5YjIyOWMxMy0wNmFiLTRmOTctYTQ3OC1mMjUzOTNmNzdlODkiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1MzMsImlhdCI6MTcwMTE3MzczMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzMzfQ.1bQJP5YuoriJc94ZwW5ssbx_BJ5SWtBVsJ6s_OzkuK8UJfiQiW1-oLgwW2bDF1HdNTN9KV3E_Xai9bC8qYTkDQ",
		5539:  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NTUzNTkzMi0wZTI5LTQ0ZGYtOGQzYi1lY2M1OTc0YmNiNWQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1NDUsImlhdCI6MTcwMTE3Mzc0NSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzQ1fQ.CefYAqWLZ1W97ImXdSRStm26eB9Zq6Kq9awl98fc23oqguJ_I6rUi8ebG65K49XJeNq-S273gM_JVOk-nrsjBA",
		826:   "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmZjJjZDBmMy00ODA3LTQ2ZjYtYmQ4Yi1kY2Y5NzY5MDcyZTUiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1NTMsImlhdCI6MTcwMTE3Mzc1MywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzUzfQ.GPiEB_u71NNaiu8bh5x5QSXrk7kIAJ6e_RSQYxS6JSl_XUdy0VVbhEND5EzTJDrOSedV-uVPqRWcCT18dWx_DQ",
	}
	tokensRSAKeyNoKid = map[int]string{
		21172: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxY2Q2OTI3NS1jMGFlLTQzMjEtYjZlYy04NGQxNzk2Y2Y4MzciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc4MTgsImlhdCI6MTcwMTE3MzAxOCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMDE4fQ.irr7e5MUIffqOS2oVRnBi0yT96qisEgngdwNdfIW7Z_9ldsmaqUEidHraBIfDwNP-U3LTVl1scqt4aKCgko6iuGqKxhyrRSdk0k_LaxdH0GgoUMbnmO80x2JMOwGQGm9BQAhzyqAMWBk70GL9GkAtblBUjFy2-9FY6V48O1UVLisQumLqs1PKKZU1KIvvWdzTFDPRj7Luhe0h9fqHi7Z7JXjH0q4c_s1QHMkvjOsIPHsz1qmoS8PFLGALq39Z2iqsF0ZSAbInmYLGB6tjqc-gmxZOdkdiDXb3NDC5Qx0shkqacY3vTi0CfcJqaChwlWVnLwoX-BmqRcGoTWmOzaMeg",
		13102: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjYzFjYTc0ZC05YmUwLTQ3ZjctYTg2MC1iYTI0ZTU5NDIzNDAiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc4ODEsImlhdCI6MTcwMTE3MzA4MSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMDgxfQ.bbHZepFGjHJqBSSLdcGWQ9cqBAlUm_WUXyi_T3lWjXZWadP6fCMDRUn23I-fp0ZxjAiFJ8vpC9LugA75tn6sHLejiRztjZ6RLG6v7olu7V1oFLZPRfM9wn2X4MnYzaA1DI9Shy-Eo3-Sr1a3lV8Vv1i3Ts4m8oe6kFu1ehtZN8HKE0Qn2m6x8qcDtx4K-GMHoT6Q0DTmyg8d-56VgKPL5xyHq7AEDR4oG9LwCeOmCxH-WrrlZzaGnRRY28ew__VQ22eDtq3aFkBT3zsBasXW6bQmq406u86QeXxQogcXwvn8EboAcJTwMl0axvw2bZiRHx4EqG0SWUzxk15mwLNN0g",
		9478:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIyMWIyYWZmNC02N2UyLTQzNGEtYmI0ZS1iMjYyNWVlYWNiYjAiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc5MDcsImlhdCI6MTcwMTE3MzEwNywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMTA3fQ.f1Litghr0k2CAUYVpe7ukuilCxQUgubqJoY2ovcFsMqGf2rA-nED3jXzx7cp9sjKghFmEq4ThTflcV2_ZK6IDNxGtNU_BO18e_dnPYZYkxkFJfz9fTvp9kkIcUYloDI8Z_LMKZvQhgsdphmQEiJd8v5BkAYc61J7Rj9Rr8bdZHyl1IDK3pqhNn8F7jQ7fNMhSgHq-5k_RZsQdG8OVZy9q_Ne5DLEs4E09Vo1xsFbd1471h5XjNVRMEOQysPdx_hs6pA81Z1YNN7NcWim7clvlO3xo9xEzQ_cCSneQ2cZxfLhDbMWgE0lnCKzWuq9pt8eDIMSguonjv7Yf3XmP9BMAg",
		20433: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5ODUzNDY3OS01OGZiLTQzN2QtOTMwYS1mOGM0Zjg1M2Y5YWEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc5MTUsImlhdCI6MTcwMTE3MzExNSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMTE1fQ.j7gFMkIreU1x8MLVYBor1Q-zwAI81YlNnQMknAmjyB_4IrGI-_agcmcRG7xeOS9LiM9Eqvlt-HqY4NGnbJENRwqx-KejV29z0R0OP53kAgpsIACSYZKLMAw58yXmNAhddkpHltKColYAYj_TL67JHwSSb8wDZkKOTbwBJAbA4bbMkkodMyKs_udcSgsKph-yCf96LDKcW3R76lKhSL8hPPInQGoiU4VuOn_TNVs6wY5fO4Bhie4VOaOL4kAYy9ULwT_lyDfyOf-nyzChz7M_4qbOjpXKOd6QMIw_1h1yFf_5fCu9mPMfRmQ2tPY1oxRbeNdf8IB-ZyUvMYNuvZZLrw",
	}
	tokensByKeyIdNoKid = map[int]string{
		22899: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzYmM3NGQwZC02YjhhLTQ3OWMtOTViOS1iMGY2YTFiOWY0YWYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1MTksImlhdCI6MTcwMTE3MzcxOSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzE5fQ.3VNlSrIAhvFImp8rQ-fS8R22pMeOwbGPmGYiuw7Qir_oQl9klzIVUVu07wa4zUu72sUDNfKkRbbiJtJhbZx2AQ",
		14211: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5YjIyOWMxMy0wNmFiLTRmOTctYTQ3OC1mMjUzOTNmNzdlODkiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1MzMsImlhdCI6MTcwMTE3MzczMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzMzfQ.1bQJP5YuoriJc94ZwW5ssbx_BJ5SWtBVsJ6s_OzkuK8UJfiQiW1-oLgwW2bDF1HdNTN9KV3E_Xai9bC8qYTkDQ",
		5539:  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NTUzNTkzMi0wZTI5LTQ0ZGYtOGQzYi1lY2M1OTc0YmNiNWQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1NDUsImlhdCI6MTcwMTE3Mzc0NSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzQ1fQ.CefYAqWLZ1W97ImXdSRStm26eB9Zq6Kq9awl98fc23oqguJ_I6rUi8ebG65K49XJeNq-S273gM_JVOk-nrsjBA",
		826:   "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmZjJjZDBmMy00ODA3LTQ2ZjYtYmQ4Yi1kY2Y5NzY5MDcyZTUiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzg1NTMsImlhdCI6MTcwMTE3Mzc1MywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczNzUzfQ.GPiEB_u71NNaiu8bh5x5QSXrk7kIAJ6e_RSQYxS6JSl_XUdy0VVbhEND5EzTJDrOSedV-uVPqRWcCT18dWx_DQ",
		21172: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxY2Q2OTI3NS1jMGFlLTQzMjEtYjZlYy04NGQxNzk2Y2Y4MzciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc4MTgsImlhdCI6MTcwMTE3MzAxOCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMDE4fQ.irr7e5MUIffqOS2oVRnBi0yT96qisEgngdwNdfIW7Z_9ldsmaqUEidHraBIfDwNP-U3LTVl1scqt4aKCgko6iuGqKxhyrRSdk0k_LaxdH0GgoUMbnmO80x2JMOwGQGm9BQAhzyqAMWBk70GL9GkAtblBUjFy2-9FY6V48O1UVLisQumLqs1PKKZU1KIvvWdzTFDPRj7Luhe0h9fqHi7Z7JXjH0q4c_s1QHMkvjOsIPHsz1qmoS8PFLGALq39Z2iqsF0ZSAbInmYLGB6tjqc-gmxZOdkdiDXb3NDC5Qx0shkqacY3vTi0CfcJqaChwlWVnLwoX-BmqRcGoTWmOzaMeg",
		13102: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjYzFjYTc0ZC05YmUwLTQ3ZjctYTg2MC1iYTI0ZTU5NDIzNDAiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc4ODEsImlhdCI6MTcwMTE3MzA4MSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMDgxfQ.bbHZepFGjHJqBSSLdcGWQ9cqBAlUm_WUXyi_T3lWjXZWadP6fCMDRUn23I-fp0ZxjAiFJ8vpC9LugA75tn6sHLejiRztjZ6RLG6v7olu7V1oFLZPRfM9wn2X4MnYzaA1DI9Shy-Eo3-Sr1a3lV8Vv1i3Ts4m8oe6kFu1ehtZN8HKE0Qn2m6x8qcDtx4K-GMHoT6Q0DTmyg8d-56VgKPL5xyHq7AEDR4oG9LwCeOmCxH-WrrlZzaGnRRY28ew__VQ22eDtq3aFkBT3zsBasXW6bQmq406u86QeXxQogcXwvn8EboAcJTwMl0axvw2bZiRHx4EqG0SWUzxk15mwLNN0g",
		9478:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIyMWIyYWZmNC02N2UyLTQzNGEtYmI0ZS1iMjYyNWVlYWNiYjAiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc5MDcsImlhdCI6MTcwMTE3MzEwNywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMTA3fQ.f1Litghr0k2CAUYVpe7ukuilCxQUgubqJoY2ovcFsMqGf2rA-nED3jXzx7cp9sjKghFmEq4ThTflcV2_ZK6IDNxGtNU_BO18e_dnPYZYkxkFJfz9fTvp9kkIcUYloDI8Z_LMKZvQhgsdphmQEiJd8v5BkAYc61J7Rj9Rr8bdZHyl1IDK3pqhNn8F7jQ7fNMhSgHq-5k_RZsQdG8OVZy9q_Ne5DLEs4E09Vo1xsFbd1471h5XjNVRMEOQysPdx_hs6pA81Z1YNN7NcWim7clvlO3xo9xEzQ_cCSneQ2cZxfLhDbMWgE0lnCKzWuq9pt8eDIMSguonjv7Yf3XmP9BMAg",
		20433: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5ODUzNDY3OS01OGZiLTQzN2QtOTMwYS1mOGM0Zjg1M2Y5YWEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3Nzc5MTUsImlhdCI6MTcwMTE3MzExNSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTczMTE1fQ.j7gFMkIreU1x8MLVYBor1Q-zwAI81YlNnQMknAmjyB_4IrGI-_agcmcRG7xeOS9LiM9Eqvlt-HqY4NGnbJENRwqx-KejV29z0R0OP53kAgpsIACSYZKLMAw58yXmNAhddkpHltKColYAYj_TL67JHwSSb8wDZkKOTbwBJAbA4bbMkkodMyKs_udcSgsKph-yCf96LDKcW3R76lKhSL8hPPInQGoiU4VuOn_TNVs6wY5fO4Bhie4VOaOL4kAYy9ULwT_lyDfyOf-nyzChz7M_4qbOjpXKOd6QMIw_1h1yFf_5fCu9mPMfRmQ2tPY1oxRbeNdf8IB-ZyUvMYNuvZZLrw",
	}
	tokensByKid = []map[int]string{
		22899: {
			22899: "eyJhbGciOiJFZERTQSIsImtpZCI6MjI4OTksInR5cCI6IkpXVCJ9.eyJqdGkiOiJiZWI5MDI5Mi1jMDdmLTRkY2QtYjU4MS1jYWViYWI3Mzk3MzgiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODI5NzQsImlhdCI6MTcwMTE3ODE3NCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MTc0fQ.WJ6J97ITaWdE5XBmw530eIGc6KOaBjAuPJwf-XnuwlqFKfDRZ01GOapF4PaUojdgFHwGVpcnVp8-cSMujQARDw",
		},
		14211: {
			14211: "eyJhbGciOiJFZERTQSIsImtpZCI6MTQyMTEsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5ZTlkNWJmZC1lNjFiLTQzZmEtOTVlMC1jYmE5MWYwMDlkYTYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMjQsImlhdCI6MTcwMTE3ODIyNCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjI0fQ.g0ksruHmBp-74rk9Dm8pU39qw1Vfxou-xsVeIg-FSLm7gDWRWN-XovmkwAamrEYqbjSR7ANQK0ykNOSgSk-1Aw",
		},
		5539: {
			5539: "eyJhbGciOiJFZERTQSIsImtpZCI6NTUzOSwidHlwIjoiSldUIn0.eyJqdGkiOiI0ZDg4OGNmZi1jMjBkLTRhZTktYjdlZi00OWQxNjUwOTA4MTQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMzYsImlhdCI6MTcwMTE3ODIzNiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjM2fQ.3kkEuku2iGyWcn2FS3evHcCIGHSm_2QHjS-u_bSSiSbmc7pvqJi1Wb7NIpwfivPxDH10GCfDjSsihEavJ7y8AA",
		},
		826: {
			826: "eyJhbGciOiJFZERTQSIsImtpZCI6ODI2LCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIxNjU4ZGRhNi0xOGE3LTRlNWUtOWE2OC1lMWM1YzRjOGVhNzIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwNTEsImlhdCI6MTcwMTE3ODI1MSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjUxfQ.oe0_DlGIPJ0AjdzCB_u58VAb912YltxiBwgeu1JIEhHSycpKeS2DXKo_6spa7DL1z7hyLBS6LoRDV53B4EdzDg",
		},
		21172: {
			21172: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjExNzIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzNDQzNjJhZS01MjZiLTRmZGQtOWM0Zi1jNmQ5ZWU2NzI4NjciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMDksImlhdCI6MTcwMTE3ODQwOSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDA5fQ.X4Vzz7JpjO38okLU7wroL80UwAJi4gR42WdBZ3jWx-4hRYk36NjkN14kbUb9z_JtPftvLI008FQd4kriFh5dAHMlIcXnE0NUKaOIdd07aiLysUZ2i7ojr3WitZFawiPcsGWo8tkCNCR3Qz-0CqLvCfI30e6eKRuWwrkq0alVWbTZtU1M6vYnkBasRFO7X0-x0Bo3Kt64owgGLzwTun2sKKHXsIFU9s04ATEKNYuvGG5j6HMcM05QEXJPPTw68Wu7hHvgDFM9y3mbCFgPd2m8YTE5bjreTo5ZtNLob79JJsynUkj8ZTju9jP5c6YUP7pcVmuLfUziwh6J3KXCqCmmvg",
		},
		13102: {
			13102: "eyJhbGciOiJSUzI1NiIsImtpZCI6MTMxMDIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1YmY2ODU4Yi01NjcyLTQ4YjUtOWQzZS0yYmQ4NDU2ZDRlMzkiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMjMsImlhdCI6MTcwMTE3ODQyMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDIzfQ.NSwcvYPZC9WLZm-g1fN31SPIeHeEAvO9WgoliRRMYSF85UZQNTJV41oDi5TmVbLGYAVoIlglCL5guUZII4nVfphvA2DG_PFZLwWxzlGitSYWWQGj1ecO-Yv8lHz2LGJwYkka5wYpLh0Y7a3iFiKD0orqMC2QWlTlLQV-Vlm3PfnzEehAPHydHBRr2wLTe2e1KisCsd1yX-oET13Oty0ENZio9CdkBB8JO4GheKeTXRGzCmfpSqF_f-GrQxCYDoNgnS981RwOWmcQRzBbi3Dm-cUCO0Pryc0gK5oyvisvtkfFZoNliZtYmbckzPHInXVhccw_87dbRquIB_znFZpUtQ",
		},
		9478: {
			9478: "eyJhbGciOiJSUzI1NiIsImtpZCI6OTQ3OCwidHlwIjoiSldUIn0.eyJqdGkiOiI2ZDc3MGE5Yi00MTA3LTQ0YzktYmExNy01ZTE1MzBkNDI3OWIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMzcsImlhdCI6MTcwMTE3ODQzNywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDM3fQ.Fsxnu5w-B4q-xeWAmLYBzUl5sgrSCXGmLMeq9-fexkO8aj5HEpcSTpnX3sKKNbS93Zxj2tnPxArpUqUh03QjFa3rmVFlK_DSY5pAr3UUSTq7wYTG9Qnvf_cA_Att1qYIhEbrnRn1mn4FGsaBA0n_92fvQ0m6cUykhyieK0Tk3p5vQ1kXtiaMWH2Y6oW3F0yoNGDshmMdpa3m66TDgmQCDEH95phB5dRKxMqvTfjzxvu7JeBmzTcVfwvuZOaB8WX8HhrkXr2D2UyYmGrXpcY7eJ_rnOJMQPgCp2sOQkIS7yMkJWW4MY9scmOXTTYbmRMbWJ0eEiuS_4G6rem7wt8twA",
		},
		20433: {
			20433: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjA0MzMsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1MjQ5ZDA0Ni00NGUzLTRjNmMtOTVkZC03Y2YwMTc0ZGNlZjMiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyNDgsImlhdCI6MTcwMTE3ODQ0OCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDQ4fQ.tVSKEOGIkMwPVC2XNc1Re3u2MJ1Lg3n6mv4xJgpYBG1CdPWnDE_rxH_FG2gDDU4O-vK_NJIBlhJM3m4k_GwKNbkGmUuONUoTul65yM_SbVmGXI04OgRErTuXSAAg1r8jQq-eVxWxUX4M0gZcM7c5s7YvS72GO8yYU2LzHIlGBAyliE4v6MosXHqSZTeeHdrToyjmdpRHEFPkUcxb2Oi1YDNDklOnmCDKjcdYcdi9TYvinQJZJYLCHBDlZYbw1KnOu_W-lefh-9k_rxiY6SEaITqxP3uNy3q3j_4-6O_McOqEVd-rvfBjbpmbV3vjkNdlI_UJW_gpP3o8RBtfsNjs1g",
		},
	}
	tokensByKidAll = []map[int]string{
		0: {
			22899: "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI0ZjNiZTIwZS1jN2JmLTQwMjUtOWRlYS01M2I5ZWE3ZTFkNDEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMTAsImlhdCI6MTcwMTE3OTQxMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDEwfQ.o2Vc0FYGJoy01cy2LTINoyCvlca8zs3S_M7fop6D9TtpRdxIltRH3EGMc4GsHWq4p2AwKivACGMRr9zl6GOBCQ",
			14211: "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiJjNGViNDhhOS01OTI3LTQ5NGQtYTE0MC0yZGE2MTU1ZTJjYzEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMjIsImlhdCI6MTcwMTE3OTQyMiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDIyfQ.mEsojatYxdke2Nvn9pncQ834mKT-m2B96mkuJ57RlojQr1Gh2Ewar_nyGlfMgxg1XpmJVR_w5MD_W_xdEdn-CQ",
			5539:  "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI1YzhmNzRhMy00Yzg1LTQzMTYtYTIwYi0zZGMzZGVmMmI5YWQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMzIsImlhdCI6MTcwMTE3OTQzMiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDMyfQ.z3EhNJTyptDvmpa6G55QtV0doag2UBheZayRtbRuC-7vQ6HpL1TRqyQlNGDjhA4v1EtULrkNYBsZyoSaHgFpBA",
			826:   "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI0Y2YyMzcwMy04N2I2LTRlNDktODY2YS02YmE2ZTdhZTE4YzYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyNDMsImlhdCI6MTcwMTE3OTQ0MywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDQzfQ.pyNXs9gR73V4Dz5jf5nm2AUnYtpeXL_RTjaW3qO7A-9RebxUBShDJei_P9oSOchDGuJ4hDHtqS24vIlycqiLBw",
			21172: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiJiYTU0MDk3Yi02MDNmLTQ2YjMtYTY4Yi1iOWUxZWMzOTJiMDIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQwNzcsImlhdCI6MTcwMTE3OTI3NywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5Mjc3fQ.hiHmxckoBGFMj8rtU7TBSHeuuVjVYJn3T3ZSurFqCRCvcKNU-2CfnwBZEGIpXClObFKyHKIAMIM_at1HNG4rKSmV9-_go1nLT7r2pAAowRHUFieuhsVmZlEUaXvVYsBhqYkxXW-FatwbkTIrjYsbIxXqEpQCEbo1z35qGpsT-N3NiF9nTdfCSLLyy7lWDxHvcAN78vBNOhIbvh6ULsSkpXNugYithGVZ81iD9mo4Swi8cJbzgB-UjdZc_0DPqQjS2bkKALA3oA_FxMd3dk-gMqiKgUArL_WSr_A8gBSPOSi7o7Jgps_8AnQu4zIqjtG-IZSS_P9qy5XLOPdKSh0w9A",
			13102: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI1OGIzYmI5Ny02Y2I2LTQyM2YtYmViMC0xYWI2YzFkNjMzNzgiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMDAsImlhdCI6MTcwMTE3OTMwMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzAwfQ.MexEDN-eHYMcEFKik4cswbB1cT8K4s_CVBYw8LjLx9ZYizNG6217r5i52vYNjnw297GshGpWUuwci4midI-fFe6-QDTB_72B3s0y-bPSMgO-bevKq_IzbjqNXV5HaIvcj1flusUWD9h5ZxVXfdgu0YwoYwyhFfnHYlW4mwVDzXHObSTGuPiCgmlGAn8SzPP0mWd9ZXpB_8DWC3KB2SxrODVl9GwGeEdYXlsYls1Y8aJ_sf4adQn6Rd2uGWZbKRfxdO7hXfrZPatI4UvsJCYPyTeDG9Z3sh4w4U1dmNQV2lwW9FZxJy-010YvPAHq6xtoyCOrO5SCzCcYiZ16hrZatA",
			9478:  "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiIzMmIwY2VhNy1hN2NmLTRkNTEtYWNjOS04ZDAxYmZjN2Q0ODciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMTAsImlhdCI6MTcwMTE3OTMxMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzEwfQ.cHEYO0raxTWJJnymcm9KlLKJRQsoHd_NWcyYFO5iGE9H1mVtsVDTLuP-odwV6OpG2QkW1V9_neDjRuoxQFhlOrSKdt-iyVhfEns_yUOM69R0rf1SwMEE3O2J3Kwdjh6mC0Qr671QTsrbGySO0tmCpQsX-DZKYwr_zUbcRLlZ8Zz5Q8Z3rdSpTVM3w0K1Lfku_Zk9GuaDg5vd38hllIF-AKsmFvSxX-lfnDNf8SyN-zesLhCPmTaxuw9f3aRGaoRzbWyNjyg9L0lbZyzFJJxrGlKPnCUetmQ0lYbWQTEht4SVdJMX-GVq8j5sOk10Ez2r65POIVgMOMP_t7rtvYZFdA",
			20433: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI3YzQ5YjU5ZC01Y2NiLTRiMDktODQ2ZS04MjBkNTYxZDE3YzIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMjMsImlhdCI6MTcwMTE3OTMyMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzIzfQ.R1-wcS2pN0NUsYvF1V99HbBdvfnpKknWoBaKme_G3JjcP3mW4zKT91o7-0cuUtu3CcCmqLPhDw1w69J89zHifv3zmV_SVwjS3GzprsAdnCp7ELY2ngLbLRMvXK4T1z269SyFxYze6e3KYhNftk05DlyP13uRy_kY0PuDkrAoy4pWWZPRlHqhaG3RGf2HpRbKnCkC_7usAAZLYziLPDSYkkOPyk6hzOWAjYElRzrD5xFvc-V8QruYnkcvNLwHxGcrWVDFaaoMT0rYtH5nhPi2vHu3GrxxmRxvvdRL1NJX0yMJOpytvWMeFGI8wff2zY7-99tF_oysvPgF0rN4SgcxDQ",
		},
		22899: {
			22899: "eyJhbGciOiJFZERTQSIsImtpZCI6MjI4OTksInR5cCI6IkpXVCJ9.eyJqdGkiOiJiZWI5MDI5Mi1jMDdmLTRkY2QtYjU4MS1jYWViYWI3Mzk3MzgiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODI5NzQsImlhdCI6MTcwMTE3ODE3NCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MTc0fQ.WJ6J97ITaWdE5XBmw530eIGc6KOaBjAuPJwf-XnuwlqFKfDRZ01GOapF4PaUojdgFHwGVpcnVp8-cSMujQARDw",
		},
		14211: {
			14211: "eyJhbGciOiJFZERTQSIsImtpZCI6MTQyMTEsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5ZTlkNWJmZC1lNjFiLTQzZmEtOTVlMC1jYmE5MWYwMDlkYTYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMjQsImlhdCI6MTcwMTE3ODIyNCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjI0fQ.g0ksruHmBp-74rk9Dm8pU39qw1Vfxou-xsVeIg-FSLm7gDWRWN-XovmkwAamrEYqbjSR7ANQK0ykNOSgSk-1Aw",
		},
		5539: {
			5539: "eyJhbGciOiJFZERTQSIsImtpZCI6NTUzOSwidHlwIjoiSldUIn0.eyJqdGkiOiI0ZDg4OGNmZi1jMjBkLTRhZTktYjdlZi00OWQxNjUwOTA4MTQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMzYsImlhdCI6MTcwMTE3ODIzNiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjM2fQ.3kkEuku2iGyWcn2FS3evHcCIGHSm_2QHjS-u_bSSiSbmc7pvqJi1Wb7NIpwfivPxDH10GCfDjSsihEavJ7y8AA",
		},
		826: {
			826: "eyJhbGciOiJFZERTQSIsImtpZCI6ODI2LCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIxNjU4ZGRhNi0xOGE3LTRlNWUtOWE2OC1lMWM1YzRjOGVhNzIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwNTEsImlhdCI6MTcwMTE3ODI1MSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjUxfQ.oe0_DlGIPJ0AjdzCB_u58VAb912YltxiBwgeu1JIEhHSycpKeS2DXKo_6spa7DL1z7hyLBS6LoRDV53B4EdzDg",
		},
		21172: {
			21172: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjExNzIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzNDQzNjJhZS01MjZiLTRmZGQtOWM0Zi1jNmQ5ZWU2NzI4NjciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMDksImlhdCI6MTcwMTE3ODQwOSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDA5fQ.X4Vzz7JpjO38okLU7wroL80UwAJi4gR42WdBZ3jWx-4hRYk36NjkN14kbUb9z_JtPftvLI008FQd4kriFh5dAHMlIcXnE0NUKaOIdd07aiLysUZ2i7ojr3WitZFawiPcsGWo8tkCNCR3Qz-0CqLvCfI30e6eKRuWwrkq0alVWbTZtU1M6vYnkBasRFO7X0-x0Bo3Kt64owgGLzwTun2sKKHXsIFU9s04ATEKNYuvGG5j6HMcM05QEXJPPTw68Wu7hHvgDFM9y3mbCFgPd2m8YTE5bjreTo5ZtNLob79JJsynUkj8ZTju9jP5c6YUP7pcVmuLfUziwh6J3KXCqCmmvg",
		},
		13102: {
			13102: "eyJhbGciOiJSUzI1NiIsImtpZCI6MTMxMDIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1YmY2ODU4Yi01NjcyLTQ4YjUtOWQzZS0yYmQ4NDU2ZDRlMzkiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMjMsImlhdCI6MTcwMTE3ODQyMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDIzfQ.NSwcvYPZC9WLZm-g1fN31SPIeHeEAvO9WgoliRRMYSF85UZQNTJV41oDi5TmVbLGYAVoIlglCL5guUZII4nVfphvA2DG_PFZLwWxzlGitSYWWQGj1ecO-Yv8lHz2LGJwYkka5wYpLh0Y7a3iFiKD0orqMC2QWlTlLQV-Vlm3PfnzEehAPHydHBRr2wLTe2e1KisCsd1yX-oET13Oty0ENZio9CdkBB8JO4GheKeTXRGzCmfpSqF_f-GrQxCYDoNgnS981RwOWmcQRzBbi3Dm-cUCO0Pryc0gK5oyvisvtkfFZoNliZtYmbckzPHInXVhccw_87dbRquIB_znFZpUtQ",
		},
		9478: {
			9478: "eyJhbGciOiJSUzI1NiIsImtpZCI6OTQ3OCwidHlwIjoiSldUIn0.eyJqdGkiOiI2ZDc3MGE5Yi00MTA3LTQ0YzktYmExNy01ZTE1MzBkNDI3OWIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMzcsImlhdCI6MTcwMTE3ODQzNywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDM3fQ.Fsxnu5w-B4q-xeWAmLYBzUl5sgrSCXGmLMeq9-fexkO8aj5HEpcSTpnX3sKKNbS93Zxj2tnPxArpUqUh03QjFa3rmVFlK_DSY5pAr3UUSTq7wYTG9Qnvf_cA_Att1qYIhEbrnRn1mn4FGsaBA0n_92fvQ0m6cUykhyieK0Tk3p5vQ1kXtiaMWH2Y6oW3F0yoNGDshmMdpa3m66TDgmQCDEH95phB5dRKxMqvTfjzxvu7JeBmzTcVfwvuZOaB8WX8HhrkXr2D2UyYmGrXpcY7eJ_rnOJMQPgCp2sOQkIS7yMkJWW4MY9scmOXTTYbmRMbWJ0eEiuS_4G6rem7wt8twA",
		},
		20433: {
			20433: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjA0MzMsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1MjQ5ZDA0Ni00NGUzLTRjNmMtOTVkZC03Y2YwMTc0ZGNlZjMiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyNDgsImlhdCI6MTcwMTE3ODQ0OCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDQ4fQ.tVSKEOGIkMwPVC2XNc1Re3u2MJ1Lg3n6mv4xJgpYBG1CdPWnDE_rxH_FG2gDDU4O-vK_NJIBlhJM3m4k_GwKNbkGmUuONUoTul65yM_SbVmGXI04OgRErTuXSAAg1r8jQq-eVxWxUX4M0gZcM7c5s7YvS72GO8yYU2LzHIlGBAyliE4v6MosXHqSZTeeHdrToyjmdpRHEFPkUcxb2Oi1YDNDklOnmCDKjcdYcdi9TYvinQJZJYLCHBDlZYbw1KnOu_W-lefh-9k_rxiY6SEaITqxP3uNy3q3j_4-6O_McOqEVd-rvfBjbpmbV3vjkNdlI_UJW_gpP3o8RBtfsNjs1g",
		},
	}
	tokensEdByKid = []map[int]string{
		0: {
			22899: "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI0ZjNiZTIwZS1jN2JmLTQwMjUtOWRlYS01M2I5ZWE3ZTFkNDEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMTAsImlhdCI6MTcwMTE3OTQxMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDEwfQ.o2Vc0FYGJoy01cy2LTINoyCvlca8zs3S_M7fop6D9TtpRdxIltRH3EGMc4GsHWq4p2AwKivACGMRr9zl6GOBCQ",
			14211: "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiJjNGViNDhhOS01OTI3LTQ5NGQtYTE0MC0yZGE2MTU1ZTJjYzEiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMjIsImlhdCI6MTcwMTE3OTQyMiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDIyfQ.mEsojatYxdke2Nvn9pncQ834mKT-m2B96mkuJ57RlojQr1Gh2Ewar_nyGlfMgxg1XpmJVR_w5MD_W_xdEdn-CQ",
			5539:  "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI1YzhmNzRhMy00Yzg1LTQzMTYtYTIwYi0zZGMzZGVmMmI5YWQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyMzIsImlhdCI6MTcwMTE3OTQzMiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDMyfQ.z3EhNJTyptDvmpa6G55QtV0doag2UBheZayRtbRuC-7vQ6HpL1TRqyQlNGDjhA4v1EtULrkNYBsZyoSaHgFpBA",
			826:   "eyJhbGciOiJFZERTQSIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI0Y2YyMzcwMy04N2I2LTRlNDktODY2YS02YmE2ZTdhZTE4YzYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQyNDMsImlhdCI6MTcwMTE3OTQ0MywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5NDQzfQ.pyNXs9gR73V4Dz5jf5nm2AUnYtpeXL_RTjaW3qO7A-9RebxUBShDJei_P9oSOchDGuJ4hDHtqS24vIlycqiLBw",
		},
		22899: {
			22899: "eyJhbGciOiJFZERTQSIsImtpZCI6MjI4OTksInR5cCI6IkpXVCJ9.eyJqdGkiOiJiZWI5MDI5Mi1jMDdmLTRkY2QtYjU4MS1jYWViYWI3Mzk3MzgiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODI5NzQsImlhdCI6MTcwMTE3ODE3NCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MTc0fQ.WJ6J97ITaWdE5XBmw530eIGc6KOaBjAuPJwf-XnuwlqFKfDRZ01GOapF4PaUojdgFHwGVpcnVp8-cSMujQARDw",
		},
		14211: {
			14211: "eyJhbGciOiJFZERTQSIsImtpZCI6MTQyMTEsInR5cCI6IkpXVCJ9.eyJqdGkiOiI5ZTlkNWJmZC1lNjFiLTQzZmEtOTVlMC1jYmE5MWYwMDlkYTYiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMjQsImlhdCI6MTcwMTE3ODIyNCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjI0fQ.g0ksruHmBp-74rk9Dm8pU39qw1Vfxou-xsVeIg-FSLm7gDWRWN-XovmkwAamrEYqbjSR7ANQK0ykNOSgSk-1Aw",
		},
		5539: {
			5539: "eyJhbGciOiJFZERTQSIsImtpZCI6NTUzOSwidHlwIjoiSldUIn0.eyJqdGkiOiI0ZDg4OGNmZi1jMjBkLTRhZTktYjdlZi00OWQxNjUwOTA4MTQiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwMzYsImlhdCI6MTcwMTE3ODIzNiwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjM2fQ.3kkEuku2iGyWcn2FS3evHcCIGHSm_2QHjS-u_bSSiSbmc7pvqJi1Wb7NIpwfivPxDH10GCfDjSsihEavJ7y8AA",
		},
		826: {
			826: "eyJhbGciOiJFZERTQSIsImtpZCI6ODI2LCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIxNjU4ZGRhNi0xOGE3LTRlNWUtOWE2OC1lMWM1YzRjOGVhNzIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMwNTEsImlhdCI6MTcwMTE3ODI1MSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4MjUxfQ.oe0_DlGIPJ0AjdzCB_u58VAb912YltxiBwgeu1JIEhHSycpKeS2DXKo_6spa7DL1z7hyLBS6LoRDV53B4EdzDg",
		},
	}
	tokensRSAByKid = []map[int]string{
		0: {
			21172: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiJiYTU0MDk3Yi02MDNmLTQ2YjMtYTY4Yi1iOWUxZWMzOTJiMDIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQwNzcsImlhdCI6MTcwMTE3OTI3NywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5Mjc3fQ.hiHmxckoBGFMj8rtU7TBSHeuuVjVYJn3T3ZSurFqCRCvcKNU-2CfnwBZEGIpXClObFKyHKIAMIM_at1HNG4rKSmV9-_go1nLT7r2pAAowRHUFieuhsVmZlEUaXvVYsBhqYkxXW-FatwbkTIrjYsbIxXqEpQCEbo1z35qGpsT-N3NiF9nTdfCSLLyy7lWDxHvcAN78vBNOhIbvh6ULsSkpXNugYithGVZ81iD9mo4Swi8cJbzgB-UjdZc_0DPqQjS2bkKALA3oA_FxMd3dk-gMqiKgUArL_WSr_A8gBSPOSi7o7Jgps_8AnQu4zIqjtG-IZSS_P9qy5XLOPdKSh0w9A",
			13102: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI1OGIzYmI5Ny02Y2I2LTQyM2YtYmViMC0xYWI2YzFkNjMzNzgiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMDAsImlhdCI6MTcwMTE3OTMwMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzAwfQ.MexEDN-eHYMcEFKik4cswbB1cT8K4s_CVBYw8LjLx9ZYizNG6217r5i52vYNjnw297GshGpWUuwci4midI-fFe6-QDTB_72B3s0y-bPSMgO-bevKq_IzbjqNXV5HaIvcj1flusUWD9h5ZxVXfdgu0YwoYwyhFfnHYlW4mwVDzXHObSTGuPiCgmlGAn8SzPP0mWd9ZXpB_8DWC3KB2SxrODVl9GwGeEdYXlsYls1Y8aJ_sf4adQn6Rd2uGWZbKRfxdO7hXfrZPatI4UvsJCYPyTeDG9Z3sh4w4U1dmNQV2lwW9FZxJy-010YvPAHq6xtoyCOrO5SCzCcYiZ16hrZatA",
			9478:  "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiIzMmIwY2VhNy1hN2NmLTRkNTEtYWNjOS04ZDAxYmZjN2Q0ODciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMTAsImlhdCI6MTcwMTE3OTMxMCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzEwfQ.cHEYO0raxTWJJnymcm9KlLKJRQsoHd_NWcyYFO5iGE9H1mVtsVDTLuP-odwV6OpG2QkW1V9_neDjRuoxQFhlOrSKdt-iyVhfEns_yUOM69R0rf1SwMEE3O2J3Kwdjh6mC0Qr671QTsrbGySO0tmCpQsX-DZKYwr_zUbcRLlZ8Zz5Q8Z3rdSpTVM3w0K1Lfku_Zk9GuaDg5vd38hllIF-AKsmFvSxX-lfnDNf8SyN-zesLhCPmTaxuw9f3aRGaoRzbWyNjyg9L0lbZyzFJJxrGlKPnCUetmQ0lYbWQTEht4SVdJMX-GVq8j5sOk10Ez2r65POIVgMOMP_t7rtvYZFdA",
			20433: "eyJhbGciOiJSUzI1NiIsImtpZCI6MCwidHlwIjoiSldUIn0.eyJqdGkiOiI3YzQ5YjU5ZC01Y2NiLTRiMDktODQ2ZS04MjBkNTYxZDE3YzIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODQxMjMsImlhdCI6MTcwMTE3OTMyMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc5MzIzfQ.R1-wcS2pN0NUsYvF1V99HbBdvfnpKknWoBaKme_G3JjcP3mW4zKT91o7-0cuUtu3CcCmqLPhDw1w69J89zHifv3zmV_SVwjS3GzprsAdnCp7ELY2ngLbLRMvXK4T1z269SyFxYze6e3KYhNftk05DlyP13uRy_kY0PuDkrAoy4pWWZPRlHqhaG3RGf2HpRbKnCkC_7usAAZLYziLPDSYkkOPyk6hzOWAjYElRzrD5xFvc-V8QruYnkcvNLwHxGcrWVDFaaoMT0rYtH5nhPi2vHu3GrxxmRxvvdRL1NJX0yMJOpytvWMeFGI8wff2zY7-99tF_oysvPgF0rN4SgcxDQ",
		},
		21172: {
			21172: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjExNzIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzNDQzNjJhZS01MjZiLTRmZGQtOWM0Zi1jNmQ5ZWU2NzI4NjciLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMDksImlhdCI6MTcwMTE3ODQwOSwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDA5fQ.X4Vzz7JpjO38okLU7wroL80UwAJi4gR42WdBZ3jWx-4hRYk36NjkN14kbUb9z_JtPftvLI008FQd4kriFh5dAHMlIcXnE0NUKaOIdd07aiLysUZ2i7ojr3WitZFawiPcsGWo8tkCNCR3Qz-0CqLvCfI30e6eKRuWwrkq0alVWbTZtU1M6vYnkBasRFO7X0-x0Bo3Kt64owgGLzwTun2sKKHXsIFU9s04ATEKNYuvGG5j6HMcM05QEXJPPTw68Wu7hHvgDFM9y3mbCFgPd2m8YTE5bjreTo5ZtNLob79JJsynUkj8ZTju9jP5c6YUP7pcVmuLfUziwh6J3KXCqCmmvg",
		},
		13102: {
			13102: "eyJhbGciOiJSUzI1NiIsImtpZCI6MTMxMDIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1YmY2ODU4Yi01NjcyLTQ4YjUtOWQzZS0yYmQ4NDU2ZDRlMzkiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMjMsImlhdCI6MTcwMTE3ODQyMywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDIzfQ.NSwcvYPZC9WLZm-g1fN31SPIeHeEAvO9WgoliRRMYSF85UZQNTJV41oDi5TmVbLGYAVoIlglCL5guUZII4nVfphvA2DG_PFZLwWxzlGitSYWWQGj1ecO-Yv8lHz2LGJwYkka5wYpLh0Y7a3iFiKD0orqMC2QWlTlLQV-Vlm3PfnzEehAPHydHBRr2wLTe2e1KisCsd1yX-oET13Oty0ENZio9CdkBB8JO4GheKeTXRGzCmfpSqF_f-GrQxCYDoNgnS981RwOWmcQRzBbi3Dm-cUCO0Pryc0gK5oyvisvtkfFZoNliZtYmbckzPHInXVhccw_87dbRquIB_znFZpUtQ",
		},
		9478: {
			9478: "eyJhbGciOiJSUzI1NiIsImtpZCI6OTQ3OCwidHlwIjoiSldUIn0.eyJqdGkiOiI2ZDc3MGE5Yi00MTA3LTQ0YzktYmExNy01ZTE1MzBkNDI3OWIiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyMzcsImlhdCI6MTcwMTE3ODQzNywibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDM3fQ.Fsxnu5w-B4q-xeWAmLYBzUl5sgrSCXGmLMeq9-fexkO8aj5HEpcSTpnX3sKKNbS93Zxj2tnPxArpUqUh03QjFa3rmVFlK_DSY5pAr3UUSTq7wYTG9Qnvf_cA_Att1qYIhEbrnRn1mn4FGsaBA0n_92fvQ0m6cUykhyieK0Tk3p5vQ1kXtiaMWH2Y6oW3F0yoNGDshmMdpa3m66TDgmQCDEH95phB5dRKxMqvTfjzxvu7JeBmzTcVfwvuZOaB8WX8HhrkXr2D2UyYmGrXpcY7eJ_rnOJMQPgCp2sOQkIS7yMkJWW4MY9scmOXTTYbmRMbWJ0eEiuS_4G6rem7wt8twA",
		},
		20433: {
			20433: "eyJhbGciOiJSUzI1NiIsImtpZCI6MjA0MzMsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1MjQ5ZDA0Ni00NGUzLTRjNmMtOTVkZC03Y2YwMTc0ZGNlZjMiLCJzdWIiOiI3OGQyN2ViMS02Y2FiLTQ0ZGMtODc5Yi1jZTdlZTYxMzg1ZmUiLCJleHAiOjE3MDE3ODMyNDgsImlhdCI6MTcwMTE3ODQ0OCwibWVuZGVyLnRlbmFudCI6IjVhYmNiNmRlN2E2NzNhMDAwMTI4N2M3MSIsIm1lbmRlci51c2VyIjp0cnVlLCJpc3MiOiJtZW5kZXIudXNlcmFkbSIsInNjcCI6Im1lbmRlci4qIiwibmJmIjoxNzAxMTc4NDQ4fQ.tVSKEOGIkMwPVC2XNc1Re3u2MJ1Lg3n6mv4xJgpYBG1CdPWnDE_rxH_FG2gDDU4O-vK_NJIBlhJM3m4k_GwKNbkGmUuONUoTul65yM_SbVmGXI04OgRErTuXSAAg1r8jQq-eVxWxUX4M0gZcM7c5s7YvS72GO8yYU2LzHIlGBAyliE4v6MosXHqSZTeeHdrToyjmdpRHEFPkUcxb2Oi1YDNDklOnmCDKjcdYcdi9TYvinQJZJYLCHBDlZYbw1KnOu_W-lefh-9k_rxiY6SEaITqxP3uNy3q3j_4-6O_McOqEVd-rvfBjbpmbV3vjkNdlI_UJW_gpP3o8RBtfsNjs1g",
		},
	}
)

func TestUserAdmMultipleKeys(t *testing.T) {
	testCases := map[string]struct {
		inEmail      model.Email
		inPassword   string
		dbUser       *model.User
		keyIds       []int
		defaultKeyId int
	}{
		"ok one key": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			keyIds:       []int{21172},
			defaultKeyId: 13102,
		},
		"ok all keys": {
			inEmail:    "foo@bar.com",
			inPassword: "correcthorsebatterystaple",

			dbUser: &model.User{
				ID:       oid.NewUUIDv5("1234").String(),
				Email:    "foo@bar.com",
				Password: `$2a$10$wMW4kC6o1fY87DokgO.lDektJO7hBXydf4B.yIWmE8hR9jOiO8way`,
			},
			keyIds: []int{
				22899,
				14211,
				5539,
				826,
				21172,
				13102,
				9478,
				20433,
			},
			defaultKeyId: 826,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			config := Config{
				Issuer:                         "mender-units",
				ExpirationTimeSeconds:          32,
				LimitSessionsPerUser:           10,
				LimitTokensPerUser:             10,
				TokenLastUsedUpdateFreqMinutes: 10,
				PrivateKeyPath:                 "testdata/private.id." + strconv.Itoa(tc.keyIds[0]) + ".pem",
				PrivateKeyFileNamePattern:      "private\\.id\\.([0-9]*)\\.pem",
			}
			handlersByKeyId := make(map[int]jwt.Handler, len(tc.keyIds)+1)
			for i := 0; i < len(tc.keyIds); i++ {
				handlersByKeyId[tc.keyIds[i]], _ = jwt.NewJWTHandler(
					"testdata/private.id."+strconv.Itoa(tc.keyIds[i])+".pem",
					"private\\.id\\.([0-9]*)\\.pem",
				)
			}
			handlersByKeyId[common.KeyIdZero], _ = jwt.NewJWTHandler(
				"testdata/private-"+strconv.Itoa(tc.defaultKeyId)+".pem",
				"private\\.id\\.([0-9]*)\\.pem",
			)

			db := &mstore.DataStore{}
			db.On("GetUserByEmail", ContextMatcher(), tc.inEmail).Return(tc.dbUser, nil)
			db.On("GetUserById", ContextMatcher(), mock.AnythingOfType("string")).Return(tc.dbUser, nil)

			db.On("SaveToken", ContextMatcher(), mock.AnythingOfType("*jwt.Token")).Return(nil)
			db.On("EnsureSessionTokensLimit", ContextMatcher(), mock.AnythingOfType("oid.ObjectID"),
				mock.AnythingOfType("int")).Return(nil)
			db.On("UpdateLoginTs", ContextMatcher(), tc.dbUser.ID).
				Return(nil)

			useradm := NewUserAdm(handlersByKeyId, db, config)
			cTenant := &mct.ClientRunner{}
			cTenant.On("GetTenant", ContextMatcher(), string(tc.inEmail), &apiclient.HttpApi{}).
				Return(&ct.Tenant{
					ID:     "5abcb6de7a673a0001287c71",
					Name:   "tenant1",
					Status: "active",
				}, nil)
			useradm = useradm.WithTenantVerification(cTenant)
			loginToken, err := useradm.Login(ctx, tc.inEmail, tc.inPassword, &LoginOptions{})
			db.On("GetTokenById", ContextMatcher(), mock.AnythingOfType("oid.ObjectID")).
				Return(loginToken, nil)

			signed, err := useradm.SignToken(ctx, loginToken)

			assert.NoError(t, err)
			token, err := handlersByKeyId[tc.keyIds[0]].FromJWT(signed)
			err = useradm.Verify(ctx, token)
			assert.NoError(t, err)

			// the default key (as loaded from testdata/private-tc.defaultKeyId.pem above
			// and assigned to KeyIdZero) is the one used to verify
			// the tokens with no kid or with kid equal 0
			token, err = handlersByKeyId[0].FromJWT(tokensByKeyIdNoKid[tc.defaultKeyId])
			err = useradm.Verify(ctx, token)
			assert.NoError(t, err)

			token, err = handlersByKeyId[0].FromJWT(tokensByKidAll[0][tc.defaultKeyId])
			err = useradm.Verify(ctx, token)
			assert.NoError(t, err)

			for i := range tc.keyIds {
				// all the tokens signed by given key and carrying the kid should be valid
				token, err = handlersByKeyId[tc.keyIds[i]].FromJWT(tokensByKid[tc.keyIds[i]][tc.keyIds[i]])
				err = useradm.Verify(ctx, token)
				assert.NoError(t, err)
			}

			for i := range tc.keyIds {
				for j := range tc.keyIds {
					if i == j {
						continue
					}
					// tokens signed by different keys cant verify
					token, err = handlersByKeyId[tc.keyIds[i]].FromJWT(tokensByKid[tc.keyIds[j]][tc.keyIds[j]])
					err = useradm.Verify(ctx, token)
					assert.Error(t, err)
				}
			}

			for i := range tc.keyIds {
				// tokens with no kid are assumed to be signed by the default key hence cant verify
				token, err = handlersByKeyId[tc.keyIds[i]].FromJWT(tokensByKeyIdNoKid[tc.keyIds[i]])
				err = useradm.Verify(ctx, token)
				assert.Error(t, err)
			}
		})
	}
}
