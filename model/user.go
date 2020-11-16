// Copyright 2020 Northern.tech AS
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
	"net/url"
	"strconv"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"

	"github.com/mendersoftware/useradm/jwt"
)

const (
	MinPasswordLength = 8
)

var (
	ErrPasswordTooShort = errors.New("password too short")
	ErrEmptyUpdate      = errors.New("no update information provided")
)

type User struct {
	// system-generated user ID
	ID string `json:"id" bson:"_id"`

	// user email address
	Email string `json:"email" bson:",omitempty" valid:"email,ascii"`

	// user password
	Password string `json:"password,omitempty" bson:"password"`

	// timestamp of the user creation
	CreatedTs *time.Time `json:"created_ts,omitempty" bson:"created_ts,omitempty"`

	// timestamp of the last user information update
	UpdatedTs *time.Time `json:"updated_ts,omitempty" bson:"updated_ts,omitempty"`

	// LoginTs is the timestamp of the last login for this user.
	LoginTs *time.Time `json:"login_ts,omitempty" bson:"login_ts,omitempty"`
}

type UserInternal struct {
	User
	PasswordHash string `json:"password_hash,omitempty" bson:"-"`
	Propagate    *bool  `json:"propagate,omitempty" bson:"-"`
}

func (u *UserInternal) ValidateNew() error {
	if u.Email == "" {
		return errors.New("email can't be empty")
	}

	if _, err := govalidator.ValidateStruct(u); err != nil {
		return err
	}

	if err := checkEmail(u.Email); err != nil {
		return err
	}

	if u.Password == "" && u.PasswordHash == "" ||
		u.Password != "" && u.PasswordHash != "" {
		return errors.New("password *or* password_hash must be provided")
	}

	if u.Password != "" {
		if err := checkPwd(u.Password); err != nil {
			return err
		}
	}

	if u.PasswordHash != "" && u.ShouldPropagate() {
		return errors.New("password_hash is not supported with 'propagate'; use 'password' instead")
	}

	return nil
}

func (u UserInternal) ShouldPropagate() bool {
	return u.Propagate == nil || *u.Propagate
}

type UserUpdate struct {

	// user email address
	Email string `json:"email,omitempty" bson:",omitempty" valid:"email"`

	// user password
	Password string `json:"password,omitempty" bson:"password,omitempty"`

	// timestamp of the last user information update
	UpdatedTs *time.Time `json:"-" bson:"updated_ts,omitempty"`

	// token used to update the user, optional
	Token *jwt.Token `json:"-" bson:"-"`

	LoginTs *time.Time `json:"-" bson:"login_ts,omitempty"`
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

	if err := checkEmail(u.Email); err != nil {
		return err
	}

	if err := checkPwd(u.Password); err != nil {
		return err
	}

	return nil
}

func (u UserUpdate) Validate() error {
	if u.Email == "" && u.Password == "" {
		return ErrEmptyUpdate
	}

	if u.Password != "" {
		if err := checkPwd(u.Password); err != nil {
			return err
		}
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

func checkEmail(email string) error {
	return nil
}

type UserFilter struct {
	ID    []string `json:"id,omitempty"`
	Email []string `json:"email,omitempty"`

	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`

	UpdatedAfter  *time.Time `json:"updated_after,omitempty"`
	UpdatedBefore *time.Time `json:"updated_before,omitempty"`
}

func (fltr *UserFilter) ParseForm(form url.Values) error {
	if ids, ok := form["id"]; ok {
		fltr.ID = ids
	}
	if email, ok := form["email"]; ok {
		fltr.Email = email
	}
	if ca := form.Get("created_after"); ca != "" {
		caInt, err := strconv.ParseInt(ca, 10, 64)
		if err != nil {
			return errors.Wrap(err,
				`invalid form parameter "created_after"`)
		}
		caUnix := time.Unix(caInt, 0)
		fltr.CreatedAfter = &caUnix
	}

	if cb := form.Get("created_before"); cb != "" {
		cbInt, err := strconv.ParseInt(cb, 10, 64)
		if err != nil {
			return errors.Wrap(err,
				`invalid form parameter "created_before"`)
		}
		cbUnix := time.Unix(cbInt, 0)
		fltr.CreatedBefore = &cbUnix
	}

	if ua := form.Get("updated_after"); ua != "" {
		uaInt, err := strconv.ParseInt(ua, 10, 64)
		if err != nil {
			return errors.Wrap(err,
				`invalid form parameter "updated_after"`)
		}
		uaUnix := time.Unix(uaInt, 0)
		fltr.UpdatedAfter = &uaUnix
	}

	if ub := form.Get("updated_before"); ub != "" {
		ubInt, err := strconv.ParseInt(ub, 10, 64)
		if err != nil {
			return errors.Wrap(err,
				`invalid form parameter "updated_before"`)
		}
		ubUnix := time.Unix(ubInt, 0)
		fltr.UpdatedBefore = &ubUnix
	}
	return nil
}
