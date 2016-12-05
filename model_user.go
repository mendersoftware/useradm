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
	"github.com/asaskevich/govalidator"
	zxcvbn "github.com/nbutton23/zxcvbn-go"
	"github.com/pkg/errors"
)

const (
	MinPasswordScore  = 3
	MinPasswordLength = 8
)

type UserModel struct {
	ID       string `json:"id" bson:"_id"`
	Email    string `json:"email" bson:",omitempty" valid:"email"`
	Password string `json:"password" bson:"password"`
}

func (u UserModel) ValidateNew() error {
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
		return errors.New("password too short")
	}

	if zxcvbn.PasswordStrength(password, nil).Score < MinPasswordScore {
		return errors.New("password too weak")
	}

	return nil
}
