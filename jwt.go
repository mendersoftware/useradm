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
	"crypto/rsa"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mendersoftware/go-lib-micro/log"
)

// JWTHandler jwt generator/verifier
type JWTHandler interface {
	ToJWT(t *Token) (string, error)
}

// JWTHandlerRS256 is an RS256-specific JWTHandler
type JWTHandlerRS256 struct {
	privKey *rsa.PrivateKey
	log     *log.Logger
}

func NewJWTHandlerRS256(privKey *rsa.PrivateKey, l *log.Logger) *JWTHandlerRS256 {
	if l == nil {
		l = log.New(log.Ctx{})
	}

	return &JWTHandlerRS256{
		privKey: privKey,
		log:     l,
	}
}

func (j *JWTHandlerRS256) ToJWT(token *Token) (string, error) {
	//generate
	jt := jwt.NewWithClaims(jwt.SigningMethodRS256, &token.Claims)

	//sign
	data, err := jt.SignedString(j.privKey)
	return data, err
}

func (j *JWTHandlerRS256) UseLog(l *log.Logger) {
	j.log = l.F(log.Ctx{})
}
