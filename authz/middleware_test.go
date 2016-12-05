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
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	mt "github.com/mendersoftware/go-lib-micro/testing"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestAuthzMiddleware(t *testing.T) {

	testCases := map[string]struct {
		token  string
		action string

		resource    string
		resourceErr error

		authErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			token:  "dummy",
			action: "GET",

			resource:    "foo:bar",
			resourceErr: nil,

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				map[string]string{"foo": "bar"},
			),
		},
		"error: missing token header": {
			token:  "",
			action: "GET",

			resource:    "foo:bar",
			resourceErr: nil,

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("missing or invalid auth header"),
			),
		},
		"error: resource id error": {
			token:  "dummy",
			action: "GET",

			resource:    "",
			resourceErr: errors.New("can't identify resource"),

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: invalid token": {
			token:  "dummy",
			action: "GET",

			resource:    "foo:bar",
			resourceErr: nil,

			authErr: ErrAuthzTokenInvalid,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("invalid jwt"),
			),
		},
		"error: unauthorized token": {
			token:  "dummy",
			action: "GET",

			resource:    "foo:bar",
			resourceErr: nil,

			authErr: ErrAuthzUnauthorized,

			checker: mt.NewJSONResponse(
				http.StatusForbidden,
				nil,
				restError("unauthorized"),
			),
		},
		"error: authorizer internal error": {
			token:  "dummy",
			action: "GET",

			resource:    "foo:bar",
			resourceErr: nil,

			authErr: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	//cases
	// x tok hdr ok, auth ok, res ok
	// x no token hdr
	// x resid err

	// Authorizer: Unauthorized
	// x Authorizer: InvTokn
	// Authorizer: internal
	for name, tc := range testCases {
		t.Logf("test case: %v", name)
		t.Logf("TOKEN: %v", tc.token)

		//setup api
		api := rest.NewApi()
		api.Use(
			&requestlog.RequestLogMiddleware{
				BaseLogger: &logrus.Logger{Out: ioutil.Discard},
			},
			&requestid.RequestIdMiddleware{},
		)
		rest.ErrorFieldName = "error"

		//setup mocks
		a := &MockAuthorizer{}
		a.On("Authorize",
			tc.token,
			tc.resource,
			tc.action).Return(tc.authErr)

		a.On("WithLog",
			mock.AnythingOfType("*log.Logger")).
			Return(a)

		resfunc := func(r *rest.Request) (string, error) {
			return tc.resource, tc.resourceErr
		}

		//finish setting up the middleware
		mw := AuthzMiddleware{
			Authz:   a,
			ResFunc: resfunc,
		}
		api.Use(&mw)

		//setup dummy handler
		api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
			w.WriteJson(map[string]string{"foo": "bar"})
		}))

		//test
		authhdr := ""
		if tc.token != "" {
			authhdr = "Bearer " + tc.token
		}

		req := makeReq(tc.action,
			"localhost",
			authhdr,
			nil)

		recorded := test.RunRequest(t, api.MakeHandler(), req)
		mt.CheckResponse(t, tc.checker, recorded)
	}
}

func makeReq(method, url, auth string, body interface{}) *http.Request {
	req := test.MakeSimpleRequest(method, url, body)

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	req.Header.Add(requestid.RequestIdHeader, "test")
	return req
}

func restError(status string) map[string]interface{} {
	return map[string]interface{}{"error": status, "request_id": "test"}
}
