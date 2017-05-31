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

package model

import (
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
)

const (
	MinPasswordLength = 8
)

var ErrPasswordTooShort = errors.New("password too short")

type User struct {
	// system-generated user ID
	ID string `json:"id" bson:"_id"`

	// user email address
	Email string `json:"email" bson:",omitempty" valid:"email"`

	// user password
	Password string `json:"password" bson:"password"`

	// timestamp of the user creation
	CreatedTs *time.Time `json:"created_ts,omitempty" bson:"created_ts,omitempty"`

	// timestamp of the last user information update
	UpdatedTs *time.Time `json:"updated_ts,omitempty" bson:"updated_ts,omitempty"`
}

func (u User) ValidateNew() error {
	if u.Email == "" {
		return errors.New("email can't be empty")
	}

	if _, err := govalidator.ValidateStruct(u); err != nil {
		return err
	}

	if u.Password == "" {
		return errors.New("password can't be empty")
	}

	if err := checkPwd(u.Password); err != nil {
		return err
	}

	return nil
}

// check password strength
func checkPwd(password string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}

	return nil
}
