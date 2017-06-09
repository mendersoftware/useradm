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

package store

import (
	"context"
	"errors"

	"github.com/mendersoftware/useradm/model"
)

var (
	// user not found
	ErrUserNotFound = errors.New("user not found")
	// token not found
	ErrTokenNotFound = errors.New("token not found")
	// duplicated email address
	ErrDuplicateEmail = errors.New("user with a given email already exists")
)

type DataStore interface {
	// CreateUser persists the user
	CreateUser(ctx context.Context, u *model.User) error
	// Update user information - password or/and email address
	UpdateUser(ctx context.Context, id string, u *model.UserUpdate) error
	//GetUserByEmail returns nil,nil if not found
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserById(ctx context.Context, id string) (*model.User, error)
	GetUsers(ctx context.Context) ([]model.User, error)
	DeleteUser(ctx context.Context, id string) error
}
