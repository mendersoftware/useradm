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
package http

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	mt "github.com/mendersoftware/go-lib-micro/testing"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/useradm/authz"
	mauthz "github.com/mendersoftware/useradm/authz/mocks"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/keys"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
	mstore "github.com/mendersoftware/useradm/store/mocks"
	useradm "github.com/mendersoftware/useradm/user"
	museradm "github.com/mendersoftware/useradm/user/mocks"
	mtesting "github.com/mendersoftware/useradm/utils/testing"
)

func makeApi(router rest.App) *rest.Api {
	api := rest.NewApi()
	api.Use(
		&requestlog.RequestLogMiddleware{
			BaseLogger: &logrus.Logger{Out: ioutil.Discard},
		},
		&requestid.RequestIdMiddleware{},
	)
	api.SetApp(router)
	return api
}

func TestAlive(t *testing.T) {
	api := makeMockApiHandler(t, nil, nil)
	req, _ := http.NewRequest("GET", "http://localhost/api/internal/v1/useradm/alive", nil)
	recorded := test.RunRequest(t, api, req)
	recorded.CodeIs(http.StatusNoContent)
	recorded.BodyIs("")
}

func TestHealthCheck(t *testing.T) {
	testCases := []struct {
		Name string

		AppError     error
		ResponseCode int
		ResponseBody interface{}
	}{{
		Name:         "ok",
		ResponseCode: http.StatusNoContent,
	}, {
		Name: "error, service unhealthy",

		AppError:     errors.New("connection error"),
		ResponseCode: http.StatusServiceUnavailable,
		ResponseBody: rest_utils.ApiError{
			Err:   "connection error",
			ReqId: "test",
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			uadm := &museradm.App{}
			uadm.On("HealthCheck", mock.MatchedBy(
				func(ctx interface{}) bool {
					if _, ok := ctx.(context.Context); ok {
						return true
					}
					return false
				},
			)).Return(tc.AppError)

			api := makeMockApiHandler(t, uadm, nil)
			req, _ := http.NewRequest(
				"GET",
				"http://localhost"+uriInternalHealth,
				nil,
			)
			req.Header.Set("X-MEN-RequestID", "test")
			recorded := test.RunRequest(t, api, req)
			recorded.CodeIs(tc.ResponseCode)
			if tc.ResponseBody != nil {
				b, _ := json.Marshal(tc.ResponseBody)
				assert.JSONEq(t,
					recorded.Recorder.Body.String(),
					string(b),
				)
			} else {
				recorded.BodyIs("")
			}
		})
	}
}

func TestUserAdmApiLogin(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inAuthHeader string

		uaToken *jwt.Token
		uaError error

		signed  string
		signErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			//"email:pass"
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			uaToken:      &jwt.Token{},

			signed: "dummytoken",

			checker: &mt.BaseResponse{
				Status:      http.StatusOK,
				ContentType: "application/jwt",
				Body:        "dummytoken",
			},
		},
		"error: unauthorized": {
			//"email:pass"
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			signed:       "initial",
			uaError:      useradm.ErrUnauthorized,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("unauthorized")),
		},
		"error: corrupt auth header": {
			inAuthHeader: "ZW1haWw6cGFzcw==",
			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("invalid or missing auth header")),
		},
		"error: useradm create error": {
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			uaError:      errors.New("useradm creation internal error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
		"error: useradm error": {
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			uaToken:      nil,
			uaError:      errors.New("useradm internal error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: sign error": {
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			uaToken:      &jwt.Token{},
			signErr:      errors.New("sign error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: tenant account suspended": {
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			signed:       "initial",
			uaError:      useradm.ErrTenantAccountSuspended,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError(useradm.ErrTenantAccountSuspended.Error())),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("Login", ctx,
				mock.AnythingOfType("string"),
				mock.AnythingOfType("string")).
				Return(tc.uaToken, tc.uaError)

			uadm.On("SignToken", ctx, tc.uaToken).Return(tc.signed, tc.signErr)

			//make mock request
			req := makeReq("POST", "http://1.2.3.4/api/management/v1/useradm/auth/login",
				tc.inAuthHeader, nil)

			api := makeMockApiHandler(t, uadm, nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiLogout(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ0ODE4OTM5MD" +
		"AsImlzcyI6Im1lbmRlciIsInN1YiI6Ijc4MWVjMmMzLTM2YTYtNGMxNC05Mj" +
		"E1LTc1Y2ZjZmQ4MzEzNiIsInNjcCI6Im1lbmRlci4qIiwiaWF0IjoxNDQ1Mj" +
		"EyODAwLCJqdGkiOiI5NzM0Zjc1Mi0wOWZkLTQ2NmItYmNjYS04ZTFmNDQwN2" +
		"JmNjUifQ.HRff3mxlygPl4ZlCA0uEalcEUrSb_xi_dnp6uDZWwAGVp-AL7NW" +
		"MhVfRw9mVNXeM2nUom7z0JUgIDGxB-24gejssiZSuZPCDJ01oyutm2xqdQKW" +
		"2LlHR5zD0m8KbNHtbHO9dPGUJATa7lHi3_QxGAqqXQYf-Jg7LwXRNqHT1EvY" +
		"gZMffuqx5i5pwpoCm9a7bTlfKxYkwuMVps3zjuliJxgqbMP3zFN9IlNB0Atb" +
		"4hEu7REd3s-2TpoIl6ztbbFDYUwz6lg1jD_q0Sbx89gw1R-auZPPZOH49szk" +
		"8bb75uaEce4BQfgIwvVyVN0NXhfN7bq6ucObZdUbNhuXmN1R6MQ"

	testCases := map[string]struct {
		logoutError error
		checker     mt.ResponseChecker
	}{
		"ok": {
			checker: &mt.BaseResponse{
				Status:      http.StatusAccepted,
				ContentType: "application/json",
			},
		},
		"error": {
			logoutError: errors.New("error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			// make mock useradm
			uadm := &museradm.App{}
			uadm.On("Logout",
				ctx,
				mock.AnythingOfType("*jwt.Token"),
			).Return(tc.logoutError)

			// make mock request
			req := makeReq("POST",
				"http://1.2.3.4/api/management/v1/useradm/auth/logout",
				"Bearer "+token,
				nil,
			)

			api := makeMockApiHandler(t, uadm, nil)

			// test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestCreateUser(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inReq *http.Request

		createUserErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"password too short": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusUnprocessableEntity,
				nil,
				restError(model.ErrPasswordTooShort.Error()),
			),
		},
		"duplicated email": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),
			createUserErr: store.ErrDuplicateEmail,

			checker: mt.NewJSONResponse(
				http.StatusUnprocessableEntity,
				nil,
				restError(store.ErrDuplicateEmail.Error()),
			),
		},
		"ok, email with ('+')": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users",
				map[string]interface{}{
					"email":    "foo+@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"invalid email (non-ascii)": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users",
				map[string]interface{}{
					"email":    "ąę@org.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("email: ąę@org.com does not validate as ascii;"),
			),
		},
		"no body": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/management/v1/useradm/users", nil),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode request body: JSON payload is empty"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("CreateUser", mtesting.ContextMatcher(),
				mock.AnythingOfType("*model.User")).
				Return(tc.createUserErr)

			api := makeMockApiHandler(t, uadm, nil)

			tc.inReq.Header.Add(requestid.RequestIdHeader, "test")
			recorded := test.RunRequest(t, api, tc.inReq)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestCreateUserForTenant(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inReq *http.Request

		createUserErr error

		checker mt.ResponseChecker

		propagate bool
	}{
		"ok": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":     "foo@foo.com",
					"password":  "foobarbar",
					"propagate": true,
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
			propagate: true,
		},
		"ok, with password hash": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":         "foo@foo.com",
					"password_hash": "foobarbar",
					"propagate":     false,
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
			propagate: false,
		},
		"error, no pass or hash": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":     "foo@foo.com",
					"propagate": true,
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("password *or* password_hash must be provided"),
			),
			propagate: true,
		},
		"error, both pass and hash provided": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":         "foo@foo.com",
					"password":      "foobarbar",
					"password_hash": "foobarbar",
					"propagate":     true,
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("password *or* password_hash must be provided"),
			),
			propagate: true,
		},
		"proagate false": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":     "foo@foo.com",
					"password":  "foobarbar",
					"propagate": false,
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
			propagate: false,
		},
		"propagate default true": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
			propagate: true,
		},
		"password too short": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(model.ErrPasswordTooShort.Error()),
			),
			propagate: true,
		},
		"duplicated email": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),
			createUserErr: store.ErrDuplicateEmail,

			checker: mt.NewJSONResponse(
				http.StatusUnprocessableEntity,
				nil,
				restError(store.ErrDuplicateEmail.Error()),
			),
			propagate: true,
		},
		"no body": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants/1/users", nil),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode request body: JSON payload is empty"),
			),
			propagate: true,
		},
		"no tenant id": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/useradm/tenants//users",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusNotFound,
				nil,
				restError("Entity not found"),
			),
			propagate: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("CreateUserInternal", mock.MatchedBy(func(c context.Context) bool {
				return identity.FromContext(c).Tenant == "1"
			}),
				mock.AnythingOfType("*model.UserInternal")).
				Return(tc.createUserErr)

			api := makeMockApiHandler(t, uadm, nil)

			tc.inReq.Header.Add(requestid.RequestIdHeader, "test")
			recorded := test.RunRequest(t, api, tc.inReq)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUpdateUser(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ0ODE4OTM5MD" +
		"AsImlzcyI6Im1lbmRlciIsInN1YiI6Ijc4MWVjMmMzLTM2YTYtNGMxNC05Mj" +
		"E1LTc1Y2ZjZmQ4MzEzNiIsInNjcCI6Im1lbmRlci4qIiwiaWF0IjoxNDQ1Mj" +
		"EyODAwLCJqdGkiOiI5NzM0Zjc1Mi0wOWZkLTQ2NmItYmNjYS04ZTFmNDQwN2" +
		"JmNjUifQ.HRff3mxlygPl4ZlCA0uEalcEUrSb_xi_dnp6uDZWwAGVp-AL7NW" +
		"MhVfRw9mVNXeM2nUom7z0JUgIDGxB-24gejssiZSuZPCDJ01oyutm2xqdQKW" +
		"2LlHR5zD0m8KbNHtbHO9dPGUJATa7lHi3_QxGAqqXQYf-Jg7LwXRNqHT1EvY" +
		"gZMffuqx5i5pwpoCm9a7bTlfKxYkwuMVps3zjuliJxgqbMP3zFN9IlNB0Atb" +
		"4hEu7REd3s-2TpoIl6ztbbFDYUwz6lg1jD_q0Sbx89gw1R-auZPPZOH49szk" +
		"8bb75uaEce4BQfgIwvVyVN0NXhfN7bq6ucObZdUbNhuXmN1R6MQ"

	testCases := map[string]struct {
		inReq *http.Request

		updateUserErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			inReq: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123",
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil,
			),
		},
		"ok with jwt token": {
			inReq: makeReq("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123",
				"Bearer "+token,
				map[string]interface{}{
					"email":    "foo@foo.com",
					"password": "foobarbar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil,
			),
		},
		"password too short": {
			inReq: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123",
				map[string]interface{}{
					"password": "foobar",
				},
			),

			checker: mt.NewJSONResponse(
				http.StatusUnprocessableEntity,
				nil,
				restError(model.ErrPasswordTooShort.Error()),
			),
		},
		"duplicated email": {
			inReq: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123",
				map[string]interface{}{
					"email": "foo@foo.com",
				},
			),
			updateUserErr: store.ErrDuplicateEmail,

			checker: mt.NewJSONResponse(
				http.StatusUnprocessableEntity,
				nil,
				restError(store.ErrDuplicateEmail.Error()),
			),
		},
		"no body": {
			inReq: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123", nil),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode request body: JSON payload is empty"),
			),
		},
		"incorrect body": {
			inReq: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/useradm/users/123",
				map[string]interface{}{
					"id": "1234",
				}),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(model.ErrEmptyUpdate.Error()),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("UpdateUser", mtesting.ContextMatcher(),
				mock.AnythingOfType("string"),
				mock.AnythingOfType("*model.UserUpdate")).
				Return(tc.updateUserErr)

			api := makeMockApiHandler(t, uadm, nil)

			tc.inReq.Header.Add(requestid.RequestIdHeader, "test")
			recorded := test.RunRequest(t, api, tc.inReq)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func makeMockApiHandler(t *testing.T, uadm useradm.App, db store.DataStore) http.Handler {
	// JWT handler
	privkey, err := keys.LoadRSAPrivate("../../crypto/private.pem")
	if !assert.NoError(t, err) {
		t.Fatalf("faied to load private key: %v", err)
	}
	jwth := jwt.NewJWTHandlerRS256(privkey)

	// API handler
	handlers := NewUserAdmApiHandlers(uadm, db, jwth)
	assert.NotNil(t, handlers)

	app, err := handlers.GetApp()
	assert.NotNil(t, app)
	assert.NoError(t, err)

	api := rest.NewApi()
	api.Use(
		&requestlog.RequestLogMiddleware{},
		&requestid.RequestIdMiddleware{},
	)

	// setup the authz middleware
	authorizer := &mauthz.Authorizer{}
	authorizer.On("Authorize",
		mock.MatchedBy(func(c context.Context) bool { return true }),
		mock.AnythingOfType("*jwt.Token"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string")).Return(nil)
	authorizer.On("WithLog",
		mock.AnythingOfType("*log.Logger")).Return(authorizer)

	authzmw := &authz.AuthzMiddleware{
		Authz:      authorizer,
		ResFunc:    ExtractResourceAction,
		JWTHandler: jwth,
	}

	ifmw := &rest.IfMiddleware{
		Condition: IsVerificationEndpoint,
		IfTrue:    authzmw,
	}

	api.Use(ifmw)

	api.SetApp(app)

	//this will override the framework's error resp to the desired one:
	// {"error": "msg"}
	// instead of:
	// {"Error": "msg"}
	rest.ErrorFieldName = "error"

	return api.MakeHandler()
}

func TestUserAdmApiPostVerify(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ0ODE4OTM5MD" +
		"AsImlzcyI6Im1lbmRlciIsInN1YiI6Ijc4MWVjMmMzLTM2YTYtNGMxNC05Mj" +
		"E1LTc1Y2ZjZmQ4MzEzNiIsInNjcCI6Im1lbmRlci4qIiwiaWF0IjoxNDQ1Mj" +
		"EyODAwLCJqdGkiOiI5NzM0Zjc1Mi0wOWZkLTQ2NmItYmNjYS04ZTFmNDQwN2" +
		"JmNjUifQ.HRff3mxlygPl4ZlCA0uEalcEUrSb_xi_dnp6uDZWwAGVp-AL7NW" +
		"MhVfRw9mVNXeM2nUom7z0JUgIDGxB-24gejssiZSuZPCDJ01oyutm2xqdQKW" +
		"2LlHR5zD0m8KbNHtbHO9dPGUJATa7lHi3_QxGAqqXQYf-Jg7LwXRNqHT1EvY" +
		"gZMffuqx5i5pwpoCm9a7bTlfKxYkwuMVps3zjuliJxgqbMP3zFN9IlNB0Atb" +
		"4hEu7REd3s-2TpoIl6ztbbFDYUwz6lg1jD_q0Sbx89gw1R-auZPPZOH49szk" +
		"8bb75uaEce4BQfgIwvVyVN0NXhfN7bq6ucObZdUbNhuXmN1R6MQ"

	testCases := map[string]struct {
		uaVerifyError error

		uaError error

		checker mt.ResponseChecker
	}{
		"ok": {
			uaVerifyError: nil,
			uaError:       nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				nil,
			),
		},
		"error: useradm unauthorized": {
			uaVerifyError: nil,
			uaError:       useradm.ErrUnauthorized,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("unauthorized"),
			),
		},
		"error: useradm internal": {
			uaVerifyError: nil,
			uaError:       errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("Verify", ctx,
				mock.AnythingOfType("*jwt.Token")).
				Return(tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq("POST",
				"http://1.2.3.4/api/internal/v1/useradm/auth/verify",
				"Bearer "+token,
				nil)

			// set these to make the middleware happy
			req.Header.Add("X-Forwarded-Uri", "/api/mgmt/0.1/someservice/some/resource")
			req.Header.Add("X-Forwarded-Method", "POST")

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)

			//make request
			req = makeReq("GET",
				"http://1.2.3.4/api/internal/v1/useradm/auth/verify",
				"Bearer "+token,
				nil)

			// set these to make the middleware happy
			req.Header.Add("X-Forwarded-Uri", "/api/mgmt/0.1/someservice/some/resource")
			req.Header.Add("X-Forwarded-Method", "GET")

			//test
			recorded = test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)

			//make request for forwarded request
			req = makeReq("GET",
				"http://1.2.3.4/api/internal/v1/useradm/auth/verify",
				"Bearer "+token,
				nil)

			// set these to make the middleware happy
			req.Header.Add("X-Forwarded-URI", "/api/mgmt/0.1/someservice/some/resource")
			req.Header.Add("X-Forwarded-Method", "POST")

			//test
			recorded = test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiGetUsers(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjQ0ODE4OTM5MDAsImlzcyI6Im1lb" +
		"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
		"NwIjoibWVuZGVyLioifQ.NzXNhh_59_03mal_" +
		"-KImArI8sfvnNFyCW0dEqmnW1gYojmTjWBBEJK" +
		"xCnh8hbHhY2mfv6Jk9wk1dEnT8_8mCACrBrw97" +
		"7oRUzlogu8yV2z1m65jpvDBGK_IsJz_GfZA2w" +
		"SBz55hkqiMEzFqswIEC46xW5RMY0vfMMSVIO7f" +
		"ncOlmTgJTdCVtr9RVDREBJIoWoC-OLGYat9ivx" +
		"yA_N_mRvu5iFPZI3FniYaBjY9k_jR62I-QPIVk" +
		"j3zWev8zKVH0Sef0lB6SAapVs1GS3rK3-oy6wk" +
		"ACNbKY1tB7Ox6CKiJ9F8Hhvh_icOtfvjCuiY-HkJL55T4wziFQNv2xU_2W7Lw"

	now := time.Now()
	testCases := map[string]struct {
		uaUsers []model.User
		uaError error

		queryString string
		checker     mt.ResponseChecker
	}{
		"ok": {
			queryString: "id=1&id=2",
			uaUsers: []model.User{
				{
					ID:    "1",
					Email: "foo@acme.com",
				},
				{
					ID:        "2",
					Email:     "bar@acme.com",
					CreatedTs: &now,
					UpdatedTs: &now,
				},
			},
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				[]model.User{
					{
						ID:    "1",
						Email: "foo@acme.com",
					},
					{
						ID:        "2",
						Email:     "bar@acme.com",
						CreatedTs: &now,
						UpdatedTs: &now,
					},
				},
			),
		},
		"ok: empty": {
			uaUsers: []model.User{},
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				[]model.User{},
			),
		},
		"error: invalid query string": {
			queryString: "%%%%",

			uaUsers: nil,
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(`api: bad form parameters: `+
					`invalid URL escape "%%%"`),
			),
		},
		"error: bad query values": {
			queryString: "created_before=an_hour_ago",

			uaUsers: nil,
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(`api: invalid form values: invalid `+
					`form parameter "created_before": `+
					`strconv.ParseInt: parsing `+
					`"an_hour_ago": invalid syntax`),
			),
		},
		"error: useradm internal": {
			uaUsers: nil,
			uaError: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			defer uadm.AssertExpectations(t)

			if tc.uaUsers != nil || tc.uaError != nil {
				fltr := model.UserFilter{}
				query, _ := url.ParseQuery(tc.queryString)
				fltr.ParseForm(query)
				uadm.On("GetUsers", ctx, fltr).
					Return(tc.uaUsers, tc.uaError)
			}

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq("GET",
				"http://1.2.3.4"+uriManagementUsers+"?"+
					tc.queryString,
				"Bearer "+token,
				nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiTenantsGetUsers(t *testing.T) {
	t.Parallel()

	now := time.Now()
	testCases := map[string]struct {
		tenant string

		queryString string
		uaUsers     []model.User
		uaError     error

		checker mt.ResponseChecker
	}{
		"ok": {
			queryString: "id=1&id=2",
			uaUsers: []model.User{
				{
					ID:    "1",
					Email: "foo@acme.com",
				},
				{
					ID:        "2",
					Email:     "bar@acme.com",
					CreatedTs: &now,
					UpdatedTs: &now,
				},
			},
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				[]model.User{
					{
						ID:    "1",
						Email: "foo@acme.com",
					},
					{
						ID:        "2",
						Email:     "bar@acme.com",
						CreatedTs: &now,
						UpdatedTs: &now,
					},
				},
			),
		},
		"ok: empty": {
			uaUsers: []model.User{},
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				[]model.User{},
			),
		},
		"error: invalid query string": {
			queryString: "%%%%",

			uaUsers: nil,
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(`api: bad form parameters: `+
					`invalid URL escape "%%%"`),
			),
		},
		"error: bad query values": {
			queryString: "created_before=an_hour_ago",

			uaUsers: nil,
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError(`api: invalid form values: invalid `+
					`form parameter "created_before": `+
					`strconv.ParseInt: parsing `+
					`"an_hour_ago": invalid syntax`),
			),
		},
		"error: useradm internal": {
			uaUsers: nil,
			uaError: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			defer uadm.AssertExpectations(t)

			if tc.uaUsers != nil || tc.uaError != nil {
				fltr := model.UserFilter{}
				query, _ := url.ParseQuery(tc.queryString)
				fltr.ParseForm(query)
				uadm.On("GetUsers", ctx, fltr).
					Return(tc.uaUsers, tc.uaError)
			}

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			repl := strings.NewReplacer(":id", tc.tenant)
			req, _ := http.NewRequest(
				"GET",
				"http://localhost"+
					repl.Replace(uriInternalTenantUsers),
				nil,
			)
			req.Header.Set("X-MEN-RequestID", "test")
			req.URL.RawQuery = tc.queryString

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiGetUser(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjQ0ODE4OTM5MDAsImlzcyI6Im1lb" +
		"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
		"NwIjoibWVuZGVyLioifQ.NzXNhh_59_03mal_" +
		"-KImArI8sfvnNFyCW0dEqmnW1gYojmTjWBBEJK" +
		"xCnh8hbHhY2mfv6Jk9wk1dEnT8_8mCACrBrw97" +
		"7oRUzlogu8yV2z1m65jpvDBGK_IsJz_GfZA2w" +
		"SBz55hkqiMEzFqswIEC46xW5RMY0vfMMSVIO7f" +
		"ncOlmTgJTdCVtr9RVDREBJIoWoC-OLGYat9ivx" +
		"yA_N_mRvu5iFPZI3FniYaBjY9k_jR62I-QPIVk" +
		"j3zWev8zKVH0Sef0lB6SAapVs1GS3rK3-oy6wk" +
		"ACNbKY1tB7Ox6CKiJ9F8Hhvh_icOtfvjCuiY-HkJL55T4wziFQNv2xU_2W7Lw"

	now := time.Now()
	testCases := map[string]struct {
		uaUser  *model.User
		uaError error

		checker mt.ResponseChecker
	}{
		"ok": {
			uaUser: &model.User{
				ID:        "1",
				Email:     "foo@acme.com",
				CreatedTs: &now,
				UpdatedTs: &now,
			},
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				&model.User{
					ID:        "1",
					Email:     "foo@acme.com",
					CreatedTs: &now,
					UpdatedTs: &now,
				},
			),
		},
		"not found": {
			uaUser:  nil,
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusNotFound,
				nil,
				restError("user not found"),
			),
		},
		"error: useradm internal": {
			uaUser:  nil,
			uaError: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("GetUser", ctx, "foo").Return(tc.uaUser, tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq("GET",
				"http://1.2.3.4/api/management/v1/useradm/users/foo",
				"Bearer "+token,
				nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiDeleteUser(t *testing.T) {
	t.Parallel()

	// we setup authz, so a real token is needed
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjQ0ODE4OTM5MDAsImlzcyI6Im1lb" +
		"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
		"NwIjoibWVuZGVyLioifQ.NzXNhh_59_03mal_" +
		"-KImArI8sfvnNFyCW0dEqmnW1gYojmTjWBBEJK" +
		"xCnh8hbHhY2mfv6Jk9wk1dEnT8_8mCACrBrw97" +
		"7oRUzlogu8yV2z1m65jpvDBGK_IsJz_GfZA2w" +
		"SBz55hkqiMEzFqswIEC46xW5RMY0vfMMSVIO7f" +
		"ncOlmTgJTdCVtr9RVDREBJIoWoC-OLGYat9ivx" +
		"yA_N_mRvu5iFPZI3FniYaBjY9k_jR62I-QPIVk" +
		"j3zWev8zKVH0Sef0lB6SAapVs1GS3rK3-oy6wk" +
		"ACNbKY1tB7Ox6CKiJ9F8Hhvh_icOtfvjCuiY-HkJL55T4wziFQNv2xU_2W7Lw"

	testCases := map[string]struct {
		uaError error

		checker mt.ResponseChecker
	}{
		"ok": {
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil,
			),
		},
		"error: useradm internal": {
			uaError: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("DeleteUser", ctx, "foo").Return(tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq("DELETE",
				"http://1.2.3.4/api/management/v1/useradm/users/foo",
				"Bearer "+token,
				nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiCreateTenant(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		uaError error
		body    interface{}
		tenant  model.NewTenant

		checker mt.ResponseChecker
	}{
		"ok": {
			uaError: nil,
			body: map[string]interface{}{
				"tenant_id": "foobar",
			},
			tenant: model.NewTenant{ID: "foobar"},

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"error: useradm internal": {
			body: map[string]interface{}{
				"tenant_id": "failing-tenant",
			},
			uaError: errors.New("some internal error"),
			tenant:  model.NewTenant{ID: "failing-tenant"},

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: no tenant id": {
			body: map[string]interface{}{
				"tenant_id": "",
			},
			tenant: model.NewTenant{},

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("tenant_id: non zero value required;"),
			),
		},
		"error: empty json": {
			tenant: model.NewTenant{},

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("JSON payload is empty"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("CreateTenant", ctx, tc.tenant).Return(tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq(http.MethodPost,
				"http://1.2.3.4/api/internal/v1/useradm/tenants",
				"",
				tc.body)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiSaveSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body interface{}

		dbError error

		checker mt.ResponseChecker
	}{
		"ok": {
			body: map[string]interface{}{
				"foo": "foo-val",
				"bar": "bar-val",
			},

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"ok, empty": {
			body: map[string]interface{}{},

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"error, not json": {
			body: "asdf",

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("cannot parse request body as json"),
			),
		},
		"error, db": {
			body: map[string]interface{}{
				"foo": "foo-val",
				"bar": "bar-val",
			},

			dbError: errors.New("generic"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock store
			db := &mstore.DataStore{}
			db.On("SaveSettings", ctx, tc.body).Return(tc.dbError)

			//make handler
			api := makeMockApiHandler(t, nil, db)

			//make request
			req := makeReq(http.MethodPost,
				"http://1.2.3.4/api/management/v1/useradm/settings",
				"",
				tc.body)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestUserAdmApiGetSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		dbSettings map[string]interface{}
		dbError    error

		checker mt.ResponseChecker
	}{
		"ok": {
			dbSettings: map[string]interface{}{
				"foo": "foo-val",
				"bar": "bar-val",
			},

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				map[string]interface{}{
					"foo": "foo-val",
					"bar": "bar-val",
				},
			),
		},
		"error: generic": {
			dbError: errors.New("failed to get settings"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock store
			db := &mstore.DataStore{}
			db.On("GetSettings", ctx).Return(tc.dbSettings, tc.dbError)

			//make handler
			api := makeMockApiHandler(t, nil, db)

			//make request
			req := makeReq(http.MethodGet,
				"http://1.2.3.4/api/management/v1/useradm/settings",
				"",
				nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
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

func TestUserAdmApiDeleteTokens(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		params string

		uaError error

		checker mt.ResponseChecker
	}{
		"ok, tenant": {
			params:  "?tenant_id=foo",
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil,
			),
		},
		"ok, tenant and user": {
			params:  "?tenant_id=foo&user_id=bar",
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil,
			),
		},
		"error: wrong params": {
			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("tenant_id must be provided"),
			),
		},
		"error: useradm internal": {
			params:  "?tenant_id=foo",
			uaError: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := mtesting.ContextMatcher()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("DeleteTokens", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm, nil)

			//make request
			req := makeReq("DELETE",
				"http://1.2.3.4/api/internal/v1/useradm/tokens"+tc.params,
				"",
				nil)

			//test
			recorded := test.RunRequest(t, api, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}
