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
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/useradm/authz"
	"github.com/mendersoftware/useradm/jwt"
)

const (
	ResourceLogin       = "auth:login"
	ResourceVerify      = "auth:verify"
	ResourceInitialUser = "users:initial"
)

// SimpleAuthz is a trivial authorizer, mostly ensuring
// proper permission check for the 'create initial user' case.
type SimpleAuthz struct {
	l *log.Logger
}

// Authorize makes SimpleAuthz implement the Authorizer interface.
func (sa *SimpleAuthz) Authorize(token *jwt.Token, resource, action string) error {
	if token == nil {
		return authz.ErrAuthzUnauthorized
	}

	// 'verify' is a special case - it will be called on all mgmt API calls in the system
	// return immediately and let the target service handle authz
	if resource == ResourceVerify {
		return nil
	}

	// bypass checks for login
	// for other resources - verify authz
	if resource == ResourceLogin {
		return nil
	}

	// check correct scope for initial user creation
	scope := token.Claims.Scope
	if scope == ScopeInitialUserCreate {
		if action == "POST" && resource == ResourceInitialUser {
			return nil
		} else {
			return authz.ErrAuthzUnauthorized
		}
	}

	// allow all for 'mender.*'
	if scope == ScopeAll {
		return nil
	}

	return authz.ErrAuthzUnauthorized
}

func (sa *SimpleAuthz) WithLog(l *log.Logger) authz.Authorizer {
	return &SimpleAuthz{
		l: l,
	}
}
