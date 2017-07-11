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

package store

import (
	"context"
	"errors"

	"github.com/mendersoftware/useradm/model"
)

var (
	// device not found
	ErrDevNotFound = errors.New("device not found")
	// device not found
	ErrTokenNotFound  = errors.New("token not found")
	ErrDuplicateEmail = errors.New("user with a given email already exists")
)

type DataStore interface {
	// IsEmpty returns true if database is empty (i.e. clean state of the
	// system)
	IsEmpty(ctx context.Context) (bool, error)
	// CreateUser persists the user
	CreateUser(ctx context.Context, u *model.User) error
	//GetUserByEmail returns nil,nil if not found
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserById(ctx context.Context, id string) (*model.User, error)
}
