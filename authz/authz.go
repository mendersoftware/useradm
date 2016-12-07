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
package authz

import (
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
)

var (
	ErrAuthzUnauthorized = errors.New("unauthorized")
	ErrAuthzNoAuthHeader = errors.New("missing or invalid auth header")
	ErrAuthzTokenInvalid = errors.New("invalid jwt")
)

// Authorizer defines the interface for checking the permissions of a given user(token) vs an action on a resource.
type Authorizer interface {
	// Authorize checks if the given user (identified by token) has permissions to an action on a resource.
	// returns:
	// nil if authorization is granted
	// ErrAuthzUnauthorized otherwise
	// ErrAuthzTokenInvalid if can't parse token
	Authorize(token, resource, action string) error
	WithLog(l *log.Logger) Authorizer
}
