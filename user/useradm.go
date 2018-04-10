// Copyright 2018 Northern.tech AS
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
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/mendersoftware/useradm/client/tenant"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/scope"
	"github.com/mendersoftware/useradm/store"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrAuthExpired  = errors.New("token expired")
	ErrAuthInvalid  = errors.New("token is invalid")
	ErrUserNotFound = errors.New("user not found")
)

type App interface {
	// Login accepts email/password, returns JWT
	Login(ctx context.Context, email, pass string) (*jwt.Token, error)
	CreateUser(ctx context.Context, u *model.User, propagate bool) error
	UpdateUser(ctx context.Context, id string, u *model.UserUpdate) error
	Verify(ctx context.Context, token *jwt.Token) error
	GetUsers(ctx context.Context) ([]model.User, error)
	GetUser(ctx context.Context, id string) (*model.User, error)
	DeleteUser(ctx context.Context, id string) error
	SetPassword(ctx context.Context, u model.UserUpdate) error

	// SignToken generates a signed
	// token using configuration & method set up in UserAdmApp
	SignToken(ctx context.Context, t *jwt.Token) (string, error)

	DeleteTokens(ctx context.Context, tenantId, userId string) error

	CreateTenant(ctx context.Context, tenant model.NewTenant) error
}

type Config struct {
	// token issuer
	Issuer string
	// token expiration time
	ExpirationTime int64
}

type ApiClientGetter func() apiclient.HttpRunner

func simpleApiClientGetter() apiclient.HttpRunner {
	return &apiclient.HttpApi{}
}

type UserAdm struct {
	// JWT serialized/deserializer
	jwtHandler   jwt.Handler
	db           store.DataStore
	config       Config
	verifyTenant bool
	cTenant      tenant.ClientRunner
	clientGetter ApiClientGetter
	tenantKeeper store.TenantDataKeeper
}

func NewUserAdm(jwtHandler jwt.Handler, db store.DataStore,
	tenantKeeper store.TenantDataKeeper, config Config) *UserAdm {

	return &UserAdm{
		jwtHandler:   jwtHandler,
		db:           db,
		config:       config,
		clientGetter: simpleApiClientGetter,
		tenantKeeper: tenantKeeper,
	}
}

func (u *UserAdm) Login(ctx context.Context, email, pass string) (*jwt.Token, error) {
	var ident identity.Identity

	if u.verifyTenant {
		// check the user's tenant
		tenant, err := u.cTenant.GetTenant(ctx, email, u.clientGetter())

		if err != nil {
			return nil, errors.Wrap(err, "failed to check user's tenant")
		}

		if tenant == nil {
			return nil, ErrUnauthorized
		}

		ident.Tenant = tenant.ID
		ctx = identity.WithContext(ctx, &ident)
	}

	//get user
	user, err := u.db.GetUserByEmail(ctx, email)
	if user == nil && err == nil {
		return nil, ErrUnauthorized
	}

	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to get user")
	}

	//verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))
	if err != nil {
		return nil, ErrUnauthorized
	}

	//generate and save token
	t := u.generateToken(user.ID, scope.All, ident.Tenant)

	err = u.db.SaveToken(ctx, t)
	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to save token")
	}

	return t, nil
}

func (u *UserAdm) generateToken(subject, scope, tenant string) *jwt.Token {
	id := uuid.NewV4().String()

	return &jwt.Token{
		Id: id,
		Claims: jwt.Claims{
			ID:        id,
			Issuer:    u.config.Issuer,
			ExpiresAt: time.Now().Unix() + u.config.ExpirationTime,
			Subject:   subject,
			Scope:     scope,
			Tenant:    tenant,
			User:      true,
		},
	}
}

func (u *UserAdm) SignToken(ctx context.Context, t *jwt.Token) (string, error) {
	return u.jwtHandler.ToJWT(t)
}

func (ua *UserAdm) CreateUser(ctx context.Context, u *model.User, propagate bool) error {
	if u.ID == "" {
		u.ID = uuid.NewV4().String()
	}

	if ua.verifyTenant && propagate {
		id := identity.FromContext(ctx)
		err := ua.cTenant.CreateUser(ctx,
			&tenant.User{
				ID:       u.ID,
				Name:     u.Email,
				TenantID: id.Tenant,
			},
			ua.clientGetter())

		if err != nil {
			switch err {
			case tenant.ErrDuplicateUser:
				return store.ErrDuplicateEmail
			default:
				return errors.Wrap(err, "useradm: failed to create user in tenantadm")
			}
		}
	}

	if err := ua.db.CreateUser(ctx, u); err != nil {
		if err == store.ErrDuplicateEmail {
			return err
		}
		return errors.Wrap(err, "useradm: failed to create user in the db")
	}

	return nil
}

func (ua *UserAdm) UpdateUser(ctx context.Context, id string, u *model.UserUpdate) error {
	if ua.verifyTenant && u.Email != "" {
		ident := identity.FromContext(ctx)
		err := ua.cTenant.UpdateUser(ctx,
			ident.Tenant,
			id,
			&tenant.UserUpdate{
				Name: u.Email,
			},
			ua.clientGetter())

		if err != nil {
			switch err {
			case tenant.ErrDuplicateUser:
				return store.ErrDuplicateEmail
			case tenant.ErrUserNotFound:
				return store.ErrUserNotFound
			default:
				return errors.Wrap(err, "useradm: failed to update user in tenantadm")
			}
		}
	}
	if err := ua.db.UpdateUser(ctx, id, u); err != nil {
		if err == store.ErrDuplicateEmail || err == store.ErrUserNotFound {
			return err
		}
		return errors.Wrap(err, "useradm: failed to update user information")
	}

	return nil
}

func (ua *UserAdm) Verify(ctx context.Context, token *jwt.Token) error {

	if token == nil {
		return ErrUnauthorized
	}

	l := log.FromContext(ctx)

	if token.Claims.User != true {
		l.Errorf("not a user token")
		return ErrUnauthorized
	}

	if ua.verifyTenant {
		if token.Claims.Tenant == "" {
			l.Errorf("Token has no tenant claim")
			return jwt.ErrTokenInvalid
		}
	} else if token.Claims.Tenant != "" {
		l.Errorf("Unexpected tenant claim: %s in the token", token.Claims.Tenant)
		return jwt.ErrTokenInvalid
	}

	//check service-specific claims - iss
	if token.Claims.Issuer != ua.config.Issuer {
		return ErrUnauthorized
	}

	user, err := ua.db.GetUserById(ctx, token.Claims.Subject)
	if user == nil && err == nil {
		return ErrUnauthorized
	}
	if err != nil {
		return errors.Wrap(err, "useradm: failed to get user")
	}

	dbToken, err := ua.db.GetTokenById(ctx, token.Id)
	if dbToken == nil && err == nil {
		return ErrUnauthorized
	}
	if err != nil {
		return errors.Wrap(err, "useradm: failed to get token")
	}

	return nil
}

func (ua *UserAdm) GetUsers(ctx context.Context) ([]model.User, error) {
	users, err := ua.db.GetUsers(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to get users")
	}

	return users, nil
}

func (ua *UserAdm) GetUser(ctx context.Context, id string) (*model.User, error) {
	user, err := ua.db.GetUserById(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to get user")
	}

	return user, nil
}

func (ua *UserAdm) DeleteUser(ctx context.Context, id string) error {
	if ua.verifyTenant {
		identity := identity.FromContext(ctx)
		err := ua.cTenant.DeleteUser(ctx, identity.Tenant, id, ua.clientGetter())

		if err != nil {
			return errors.Wrap(err, "useradm: failed to delete user in tenantadm")
		}
	}

	err := ua.db.DeleteUser(ctx, id)
	if err != nil {
		return errors.Wrap(err, "useradm: failed to delete user")
	}

	return nil
}

// WithTenantVerification produces a UserAdm instance which enforces
// tenant verification vs the tenantadm service upon /login.
func (u *UserAdm) WithTenantVerification(c tenant.ClientRunner) *UserAdm {
	u.verifyTenant = true
	u.cTenant = c
	return u
}

func (u *UserAdm) CreateTenant(ctx context.Context, tenant model.NewTenant) error {
	if err := u.tenantKeeper.MigrateTenant(ctx, tenant.ID); err != nil {
		return errors.Wrapf(err, "failed to apply migrations for tenant %v", tenant.ID)
	}
	return nil
}

func (ua *UserAdm) SetPassword(ctx context.Context, uu model.UserUpdate) error {
	u, err := ua.db.GetUserByEmail(ctx, uu.Email)
	if err != nil {
		return errors.Wrap(err, "useradm: failed to get user by email")

	}
	if u == nil {
		return ErrUserNotFound
	}

	err = ua.db.UpdateUser(ctx, u.ID, &uu)
	return errors.Wrap(err, "useradm: failed to update user information")
}

func (ua *UserAdm) DeleteTokens(ctx context.Context, tenantId, userId string) error {
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenantId,
	})

	var err error

	if userId != "" {
		err = ua.db.DeleteTokensByUserId(ctx, userId)
	} else {
		err = ua.db.DeleteTokens(ctx)
	}

	if err != nil && err != store.ErrTokenNotFound {
		return errors.Wrapf(err, "failed to delete tokens for tenant: %v, user id: %v", tenantId, userId)
	}

	return nil
}
