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
	// immediately fail when no token present
	if token == nil {
		return authz.ErrAuthzUnauthorized
	}

	// bypass checks for login - doesn't use token at all
	if resource == ResourceLogin {
		return nil
	}

	// allow just a single action for ScopeInitialUserCreate
	scope := token.Claims.Scope
	if scope == ScopeInitialUserCreate {
		if action == "POST" && resource == ResourceInitialUser {
			return nil
		} else {
			return authz.ErrAuthzUnauthorized
		}
	} else if scope == ScopeAll {
		// allow all actions for ScopeAll
		// note: this rule also applies to POST /verify, called upon every mgmt api request
		return nil
	}

	return authz.ErrAuthzUnauthorized
}

func (sa *SimpleAuthz) WithLog(l *log.Logger) authz.Authorizer {
	return &SimpleAuthz{
		l: l,
	}
}
