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
	"time"

	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/scope"
	"github.com/mendersoftware/useradm/store"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrAuthExpired  = errors.New("token expired")
	ErrAuthInvalid  = errors.New("token is invalid")
)

type App interface {
	// Login accepts email/password, returns JWT
	Login(ctx context.Context, email, pass string) (*jwt.Token, error)
	CreateUser(ctx context.Context, u *model.User) error
	Verify(ctx context.Context, token *jwt.Token) error

	// SignToken returns a function that can be used for generating a signed
	// token using configuration & method set up in UserAdmApp
	SignToken(ctx context.Context) jwt.SignFunc
}

type Config struct {
	// token issuer
	Issuer string
	// token expiration time
	ExpirationTime int64
}

type UserAdm struct {
	// JWT serialized/deserializer
	jwtHandler jwt.JWTHandler
	db         store.DataStore
	config     Config
}

func NewUserAdm(jwtHandler jwt.JWTHandler, db store.DataStore, config Config) *UserAdm {
	return &UserAdm{
		jwtHandler: jwtHandler,
		db:         db,
		config:     config,
	}
}

func (u *UserAdm) Login(ctx context.Context, email, pass string) (*jwt.Token, error) {
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

	//generate token
	t := u.generateToken(user.ID, scope.All)

	return t, nil
}

func (u *UserAdm) generateToken(subject, scope string) *jwt.Token {
	return &jwt.Token{
		Claims: jwt.Claims{
			ID:        uuid.NewV4().String(),
			Issuer:    u.config.Issuer,
			ExpiresAt: time.Now().Unix() + u.config.ExpirationTime,
			Subject:   subject,
			Scope:     scope,
		},
	}
}

func (u *UserAdm) SignToken(ctx context.Context) jwt.SignFunc {
	return func(t *jwt.Token) (string, error) {
		return u.jwtHandler.ToJWT(t)
	}
}

func (ua *UserAdm) CreateUser(ctx context.Context, u *model.User) error {
	u.ID = uuid.NewV4().String()

	if err := ua.db.CreateUser(ctx, u); err != nil {
		if err == store.ErrDuplicateEmail {
			return err
		}
		return errors.Wrap(err, "useradm: failed to create user in the db")
	}

	return nil
}

func (ua *UserAdm) Verify(ctx context.Context, token *jwt.Token) error {
	if token == nil {
		return ErrUnauthorized
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

	return nil
}
