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
	"time"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrUserNotInitial = errors.New("user database not empty")
)

type UserAdmApp interface {
	// Login accepts email/password, returns JWT
	Login(email, pass string) (*jwt.Token, error)
	CreateUser(u *UserModel) error
	CreateUserInitial(u *UserModel) error

	// SignToken returns a function that can be used for generating a signed
	// token using configuration & method set up in UserAdmApp
	SignToken() jwt.SignFunc
}

type UserAdmConfig struct {
	// token issuer
	Issuer string
	// token expiration time
	ExpirationTime int64
}

type UserAdm struct {
	// JWT serialized/deserializer
	jwtHandler jwt.JWTHandler
	db         DataStore
	config     UserAdmConfig
	log        *log.Logger
}

func NewUserAdm(jwtHandler jwt.JWTHandler, db DataStore, config UserAdmConfig, log *log.Logger) *UserAdm {
	return &UserAdm{
		jwtHandler: jwtHandler,
		db:         db,
		config:     config,
		log:        log,
	}
}

func (u *UserAdm) Login(email, pass string) (*jwt.Token, error) {
	if email == "" && pass == "" {
		return u.doInitialLogin()
	}

	return u.doRegularLogin(email, pass)
}

// implements the initial/first-time login flow
// issues a token for user creation if no users defined yet
func (u *UserAdm) doInitialLogin() (*jwt.Token, error) {
	empty, err := u.db.IsEmpty()
	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to query database")
	}
	if !empty {
		return nil, ErrUnauthorized
	}

	t := u.generateToken("initial", ScopeInitialUserCreate)

	return t, nil
}

// implements the regular login flow
// needs real creds, issues a general-purpose token
func (u *UserAdm) doRegularLogin(email, password string) (*jwt.Token, error) {
	//get user
	user, err := u.db.GetUserByEmail(email)
	if user == nil && err == nil {
		return nil, ErrUnauthorized
	}

	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to get user")
	}

	//verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, ErrUnauthorized
	}

	//generate token
	t := u.generateToken(user.ID, ScopeAll)

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

func (u *UserAdm) SignToken() jwt.SignFunc {
	return func(t *jwt.Token) (string, error) {
		return u.jwtHandler.ToJWT(t)
	}
}

func (ua *UserAdm) CreateUser(u *UserModel) error {
	u.ID = uuid.NewV4().String()

	if err := ua.db.CreateUser(u); err != nil {
		if err == ErrDuplicateEmail {
			return err
		}
		return errors.Wrap(err, "useradm: failed to create user in the db")
	}

	return nil
}

func (ua *UserAdm) CreateUserInitial(u *UserModel) error {
	empty, err := ua.db.IsEmpty()
	if err != nil {
		return errors.Wrap(err, "useradm: failed to check if db is empty")
	}

	if empty {
		return ua.CreateUser(u)
	} else {
		return ErrUserNotInitial
	}
}
