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
	"net/http"
	"strings"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
)

// AuthzMiddleware checks the authorization on a given request.
// It retrieves the requested resource and action, and delegates the authz check to an Authorizer.
type AuthzMiddleware struct {
	Authz   Authorizer
	ResFunc ResourceExtractor
}

// ResourceExtractor extract resource IDs from requests.
type ResourceExtractor func(r *rest.Request) (string, error)

// MiddlewareFunc makes AuthzMiddleware implement the Middleware interface.
func (mw *AuthzMiddleware) MiddlewareFunc(h rest.HandlerFunc) rest.HandlerFunc {
	return func(w rest.ResponseWriter, r *rest.Request) {
		l := requestlog.GetRequestLogger(r.Env)

		//get token, no token header = http 401
		token := extractToken(r.Header)
		if token == "" {
			rest_utils.RestErrWithLog(w, r, l, ErrAuthzNoAuthHeader, http.StatusUnauthorized)
			return
		}

		// extract resource id
		resid, err := mw.ResFunc(r)
		if err != nil {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
			return
		}

		//authorize, no authz = http 403
		a := mw.Authz.WithLog(l)
		err = a.Authorize(token, resid, r.Method)
		if err != nil {
			if err == ErrAuthzUnauthorized {
				rest_utils.RestErrWithLog(w, r, l,
					ErrAuthzUnauthorized, http.StatusForbidden)
			} else if err == ErrAuthzTokenInvalid {
				rest_utils.RestErrWithLog(w, r, l,
					ErrAuthzTokenInvalid, http.StatusUnauthorized)
			} else {
				rest_utils.RestErrWithLogInternal(w, r, l, err)
			}
			return
		}

		h(w, r)
	}
}

// extracts JWT from authorization header
func extractToken(header http.Header) string {
	const authHeaderName = "Authorization"
	authHeader := header.Get(authHeaderName)
	if authHeader == "" {
		return authHeader
	}
	tokenStr := strings.Replace(authHeader, "Bearer", "", 1)
	tokenStr = strings.Replace(tokenStr, "bearer", "", 1)
	return strings.TrimSpace(tokenStr)
}
