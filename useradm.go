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
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type UserAdmApp interface {
	// Login accepts email/password, returns JWT
	Login(email, pass string) (*jwt.Token, error)
}

type UserAdm struct {
	jwtHandler JWTHandler
}

func NewUserAdm(jwtHandler JWTHandler) *UserAdm {
	return &UserAdm{jwtHandler: jwtHandler}
}

// this is a dummy method for now - always returns a valid JWT; no db interaction
func (u *UserAdm) Login(email, pass string) (*jwt.Token, error) {
	//TODO: pull this from the db after verification
	userId := "dummy_user_id"

	token, err := u.jwtHandler.GenerateToken(userId)
	if err != nil {
		return nil, errors.Wrap(err, "useradm: failed to generate token")
	}

	return token, nil
}
