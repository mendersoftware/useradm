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

package store

import (
	"context"
	"errors"
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/oid"

	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/model"
)

var (
	// user not found
	ErrUserNotFound = errors.New("user not found")
	// token not found
	ErrTokenNotFound = errors.New("token not found")
	// duplicated email address
	ErrDuplicateEmail = errors.New("user with a given email already exists")
	// password mismatch
	ErrCurrentPasswordMismatch = errors.New("current password mismatch")
)

//go:generate ../utils/mockgen.sh
type DataStore interface {
	// Ping the storage service - verifying network connection.
	Ping(ctx context.Context) error
	// CreateUser persists the user
	CreateUser(ctx context.Context, u *model.User) error
	// Update user information - password or/and email address and
	// returns the updated user
	UpdateUser(ctx context.Context, id string, u *model.UserUpdate) (*model.User, error)
	UpdateLoginTs(ctx context.Context, id string) error
	//GetUserByEmail returns nil,nil if not found
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	// GetUserForLogin
	GetUserForLogin(ctx context.Context, email string, loginTS time.Time) (*model.User, error)
	GetUserById(ctx context.Context, id string) (*model.User, error)
	GetUserAndPasswordById(ctx context.Context, id string) (*model.User, error)
	GetUsers(ctx context.Context, fltr model.UserFilter) ([]model.User, error)
	DeleteUser(ctx context.Context, id string) error
	SaveToken(ctx context.Context, token *jwt.Token) error
	GetTokenById(ctx context.Context, id oid.ObjectID) (*jwt.Token, error)
	DeleteToken(ctx context.Context, tokenID oid.ObjectID) error

	// deletes all tenant's tokens (identity in context)
	DeleteTokens(ctx context.Context) error

	// deletes user tokens
	DeleteTokensByUserId(ctx context.Context, userId string) error
	DeleteTokensByUserIdExceptCurrentOne(
		ctx context.Context,
		userId string,
		tokenID oid.ObjectID,
	) error

	SaveSettings(ctx context.Context, s map[string]interface{}) error
	GetSettings(ctx context.Context) (map[string]interface{}, error)
}

// TenantDataKeeper is an interface for executing administrative opeartions on
// tenants
//go:generate ../utils/mockgen.sh
type TenantDataKeeper interface {
	// MigrateTenant migrates given tenant to the latest DB version
	MigrateTenant(ctx context.Context, id string) error
}
