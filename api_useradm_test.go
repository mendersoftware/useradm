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
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	mt "github.com/mendersoftware/go-lib-micro/testing"
	"github.com/mendersoftware/useradm/authz"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
		"ok: regular flow": {
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
		"ok: initial flow": {
			inAuthHeader: "",
			signed:       "initial",

			checker: &mt.BaseResponse{
				Status:      http.StatusOK,
				ContentType: "application/jwt",
				Body:        "initial",
			},
		},
		"error: unauthorized": {
			//"email:pass"
			inAuthHeader: "Basic ZW1haWw6cGFzcw==",
			signed:       "initial",
			uaError:      ErrUnauthorized,

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
	}

	for name, tc := range testCases {
		t.Logf("test case: %v", name)

		//make mock useradm
		useradm := &mockUserAdmApp{
			sign: func(_ *jwt.Token) (string, error) {
				return tc.signed, tc.signErr
			},
		}
		useradm.On("Login",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string")).
			Return(tc.uaToken, tc.uaError)
		useradm.On("SignToken").Return()

		//make mock request
		req := makeReq("POST", "http://1.2.3.4/api/0.1.0/auth/login", tc.inAuthHeader, nil)

		//make handler
		factory := func(l *log.Logger) (UserAdmApp, error) {
			return useradm, nil
		}

		api := makeMockApiHandler(t, factory)

		//test
		recorded := test.RunRequest(t, api, req)
		mt.CheckResponse(t, tc.checker, recorded)
	}
}

func makeMockApiHandler(t *testing.T, f UserAdmFactory) http.Handler {
	handlers := NewUserAdmApiHandlers(f)
	assert.NotNil(t, handlers)

	app, err := handlers.GetApp()
	assert.NotNil(t, app)
	assert.NoError(t, err)

	api := rest.NewApi()
	api.Use(
		&requestlog.RequestLogMiddleware{},
		&requestid.RequestIdMiddleware{},
	)

	//setup the authz middleware
	privkey := loadPrivKey("crypto/private.pem", t)

	//allow access without authz on /login
	//all other enpoinds protected
	authorizer := &SimpleAuthz{}
	authzmw := &authz.AuthzMiddleware{
		Authz:      authorizer,
		ResFunc:    extractResourceId,
		JWTHandler: jwt.NewJWTHandlerRS256(privkey, nil),
	}

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

	api.SetApp(app)

	//this will override the framework's error resp to the desired one:
	// {"error": "msg"}
	// instead of:
	// {"Error": "msg"}
	rest.ErrorFieldName = "error"

	return api.MakeHandler()
}

func TestUserAdmApiPostUsersInitial(t *testing.T) {
	t.Parallel()

	// token error - incorrect scope

	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
		"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik" +
		"1lbmRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiw" +
		"ic2NwIjoibWVuZGVyLnVzZXJzLmluaXRpYWwu" +
		"Y3JlYXRlIn0.vcg5XS81mZT9oFpFiPsU5KYz5" +
		"UAaSWnmlxopW5qsrcV3IQ4mODo63rqvZnfLgc" +
		"eBW3qfdmi025BLhiajtEGHhggXZdTD5Q_3q08" +
		"dqWFaePI42FzmAITqmzWAnNS78xUh0EZ3uNnz" +
		"RPPWDOV5IDpsJHtV44_vZ341dxssTWEsuSMxm" +
		"Jk8_VergMGQ8hJSk7_ioAP11kRCuKz1R5ruPS" +
		"kicrrw5Z9vmx86zFPLXhy98Jz3cuMKhy4npEu" +
		"3GhdTYhWIFv2_xwCFTEamWB1PQ7JVkNdjMHt7" +
		"9AxEXYoDxYpCWvjdeEXs7gVPFvMespq3fRGxw" +
		"IvgDV1UmL2nb9AlzkInJw"

	invalidTokenScope := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
		"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik" +
		"1lbmRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiw" +
		"ic2NwIjoic29tZS5pbnZhbGlkLnNjb3BlIn0." +
		"VNkvs52FSJpFcacnqydoTmHdmOBjLq6OXbKLa" +
		"f6dR3iRxry-75Gan2j2ZtZqt2tq8bpf_lWRdh" +
		"kCCQcA542jrIkWrqvY_w632JDNh_2wyglG9R_" +
		"6Xitz31HVE-Wj4WQzmAQyl3my0DWiMn-dtbox" +
		"hp9jZfHUjYxJzus7fpRkkew0ckmiDS-ULFdAe" +
		"WBuAQHypVwtpCN7maFrWbATJ29We5T8QQpSi2" +
		"6RrW8I8NyXQE2YRR2mGoyHLjnEQdxJHV8U8xY" +
		"t8nde8Fe1NQVTeNz0tTgQyUByLPt2NpIBkb29" +
		"NA1ygq8umitZdh13m_gwNnFxAbrEGRlFLIIVK" +
		"TtzWorsZw"

	testCases := map[string]struct {
		inToken string
		inBody  interface{}

		uaError error

		checker mt.ResponseChecker
	}{
		"ok": {
			inToken: validToken,
			inBody: UserModel{
				Email:    "email@foo.com",
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil,
			),
		},
		"error: invalid body": {
			inToken: validToken,
			inBody:  "asdf",

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode user info: json: cannot unmarshal string into Go value of type main.UserModel"),
			),
		},
		"error: valid body, no email": {
			inToken: validToken,
			inBody: UserModel{
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("invalid user info: email can't be empty"),
			),
		},
		"error: valid body, invalid email": {
			inToken: validToken,
			inBody: UserModel{
				Email:    "username",
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("invalid user info: Email: username does not validate as email;"),
			),
		},
		"error: valid body, missing password": {
			inToken: validToken,
			inBody: UserModel{
				Email: "foo@bar.com",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("invalid user info: password can't be empty"),
			),
		},
		"error: valid body, password to short": {
			inToken: validToken,
			inBody: UserModel{
				Email:    "foo@bar.com",
				Password: "asdf123",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("invalid user info: password too short"),
			),
		},
		"error: valid body, password to weak": {
			inToken: validToken,
			inBody: UserModel{
				Email:    "foo@bar.com",
				Password: "asdf1234",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("invalid user info: password too weak"),
			),
		},
		"error: useradm error": {
			inToken: validToken,
			inBody: UserModel{
				Email:    "email@foo.com",
				Password: "correcthorsebatterystaple",
			},

			uaError: errors.New("some internal useardm error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: no token": {
			inToken: "",
			inBody: UserModel{
				Email:    "email@foo.com",
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("missing or invalid auth header"),
			),
		},
		"error: invalid token": {
			inToken: "asdf",
			inBody: UserModel{
				Email:    "email@foo.com",
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("invalid jwt"),
			),
		},
		"error: token valid, incorrect scope": {
			inToken: invalidTokenScope,
			inBody: UserModel{
				Email:    "email@foo.com",
				Password: "correcthorsebatterystaple",
			},

			uaError: nil,

			checker: mt.NewJSONResponse(
				http.StatusForbidden,
				nil,
				restError("unauthorized"),
			),
		},
	}
	for name, tc := range testCases {
		t.Logf("test case: %v", name)

		//make mock useradm
		useradm := &mockUserAdmApp{}
		useradm.On("CreateUserInitial",
			mock.AnythingOfType("*main.UserModel")).
			Return(tc.uaError)

		//make handler
		factory := func(l *log.Logger) (UserAdmApp, error) {
			return useradm, nil
		}

		api := makeMockApiHandler(t, factory)

		//make request
		authHdr := ""
		if tc.inToken != "" {
			authHdr = "Bearer " + tc.inToken
		}

		req := makeReq("POST",
			"http://1.2.3.4/api/0.1.0/users/initial",
			authHdr,
			tc.inBody)

		//test
		recorded := test.RunRequest(t, api, req)
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
