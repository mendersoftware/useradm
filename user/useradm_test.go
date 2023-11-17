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
	"net/http"
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
