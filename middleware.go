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
	"fmt"
	"net/http"
	"strings"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/accesslog"
	dlog "github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/useradm/authz"
)

const (
	EnvProd   = "prod"
	EnvDev    = "dev"
	EnvNoAuth = "noauth"
)

var (
	DefaultDevStack = []rest.Middleware{

		// logging
		&requestlog.RequestLogMiddleware{},
		&accesslog.AccessLogMiddleware{Format: accesslog.SimpleLogFormat},
		&rest.TimerMiddleware{},
		&rest.RecorderMiddleware{},

		// catches the panic errors that occur with stack trace
		&rest.RecoverMiddleware{
			EnableResponseStackTrace: true,
		},

		// json pretty print
		&rest.JsonIndentMiddleware{},

		// verifies the request Content-Type header
		// The expected Content-Type is 'application/json'
		// if the content is non-null
		&rest.ContentTypeCheckerMiddleware{},
		&requestid.RequestIdMiddleware{},
	}

	DefaultProdStack = []rest.Middleware{

		// logging
		&requestlog.RequestLogMiddleware{},
		&accesslog.AccessLogMiddleware{Format: accesslog.SimpleLogFormat},
		&rest.TimerMiddleware{},
		&rest.RecorderMiddleware{},

		// catches the panic errors
		&rest.RecoverMiddleware{},

		// response compression
		&rest.GzipMiddleware{},

		// verifies the request Content-Type header
		// The expected Content-Type is 'application/json'
		// if the content is non-null
		&rest.ContentTypeCheckerMiddleware{},
		&requestid.RequestIdMiddleware{},
	}

	middlewareMap = map[string][]rest.Middleware{
		EnvProd: DefaultProdStack,
		EnvDev:  DefaultDevStack,
		// this is a temporary solution until work on user authentication is
		// done and UI part is implemented
		EnvNoAuth: DefaultDevStack,
	}
)

func SetupMiddleware(api *rest.Api, mwtype string, authorizer authz.Authorizer) error {

	l := dlog.New(dlog.Ctx{})

	l.Infof("setting up %s middleware", mwtype)

	mwstack, ok := middlewareMap[mwtype]
	if !ok {
		return fmt.Errorf("incorrect middleware type: %s", mwtype)
	}

	api.Use(mwstack...)

	api.Use(&rest.CorsMiddleware{
		RejectNonCorsRequests: false,

		// Should be tested with some list
		OriginValidator: func(origin string, request *rest.Request) bool {
			// Accept all requests
			return true
		},

		// Preflight request cache length
		AccessControlMaxAge: 60,

		// Allow authentication requests
		AccessControlAllowCredentials: true,

		// Allowed headers
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},

		// Allowed headers
		AllowedHeaders: []string{
			"Accept",
			"Allow",
			"Content-Type",
			"Origin",
			"Authorization",
			"Accept-Encoding",
			"Access-Control-Request-Headers",
			"Header-Access-Control-Request",
		},

		// Headers that can be exposed to JS
		AccessControlExposeHeaders: []string{
			"Location",
			"Link",
		},
	})

	// TODO: remove below once user authentication is fully implemented
	if mwtype == EnvNoAuth {
		// do not use `AuthzMiddleware` and return immediately instead
		l.Warn("running without authorization API and should not be used in production")
		return nil
	}

	authzmw := &authz.AuthzMiddleware{
		Authz:   authorizer,
		ResFunc: extractResourceId,
	}

	//allow access without authz on /login
	//all other enpoinds protected
	ifmw := &rest.IfMiddleware{
		Condition: func(r *rest.Request) bool {
			if r.URL.Path == uriAuthLogin && r.Method == http.MethodPost {
				return true
			} else {
				return false
			}
		},
		IfFalse: authzmw,
	}

	api.Use(ifmw)

	return nil
}

// extracts resource ID from the request url
func extractResourceId(r *rest.Request) (string, error) {
	//tokenize everything past the api version
	path := r.URL.Path

	path = strings.Replace(path, uriBase, "", 1)

	return strings.Replace(path, "/", ":", 1), nil
}
