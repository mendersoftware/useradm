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
	"github.com/satori/go.uuid"
	"time"
)

// token claim names
const (
	jwtClaimIssuer     = "iss"
	jwtClaimSubject    = "sub"
	jwtClaimExpiration = "exp"
	jwtClaimTokenId    = "jti"
)

// JWTHandler jwt generator/verifier
type JWTHandler interface {
	GenerateToken(subject string) (*jwt.Token, error)
}

// JWTHandlerRS256 is an RS256-specific JWTHandler
type JWTHandlerRS256 struct {
	issuer       string
	expiresInSec int64
	privKey      *rsa.PrivateKey
	log          *log.Logger
}

func NewJWTHandlerRS256(privKey *rsa.PrivateKey, issuer string, expiresInSec int64, l *log.Logger) *JWTHandlerRS256 {
	if l == nil {
		l = log.New(log.Ctx{})
	}

	return &JWTHandlerRS256{
		issuer:       issuer,
		expiresInSec: expiresInSec,
		privKey:      privKey,
		log:          l,
	}
}

func (j *JWTHandlerRS256) GenerateToken(subject string) (*jwt.Token, error) {
	//set claims
	claims := jwt.StandardClaims{
		Issuer:    j.issuer,
		ExpiresAt: time.Now().Unix() + j.expiresInSec,
		Subject:   subject,
		Id:        uuid.NewV4().String(),
	}

	//generate
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//sign
	tokenString, err := token.SignedString(j.privKey)
	if err != nil {
		return nil, err
	}

	//note: abusing the jwt.Token slightly here, by reusing the 'Raw' field
	//jwt does this only on Parse()
	token.Raw = tokenString

	return token, nil
}
func (j *JWTHandlerRS256) UseLog(l *log.Logger) {
	j.log = l.F(log.Ctx{})
}
