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
package http

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	mt "github.com/mendersoftware/go-lib-micro/testing"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/useradm/authz"
	mauthz "github.com/mendersoftware/useradm/authz/mocks"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/keys"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
	"github.com/mendersoftware/useradm/user"
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
	}

	for name, tc := range testCases {
		t.Logf("test case: %v", name)

		ctx := context.TODO()

		//make mock useradm
		uadm := &museradm.App{}
		uadm.On("Login", ctx,
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string")).
			Return(tc.uaToken, tc.uaError)

		uadm.On("SignToken", ctx, tc.uaToken).Return(tc.signed, tc.signErr)

		//make mock request
		req := makeReq("POST", "http://1.2.3.4/api/0.1.0/auth/login", tc.inAuthHeader, nil)

		api := makeMockApiHandler(t, uadm)

		//test
		recorded := test.RunRequest(t, api, req)
		mt.CheckResponse(t, tc.checker, recorded)
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
				"http://1.2.3.4/api/0.1.0/users",
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
				"http://1.2.3.4/api/0.1.0/users",
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
				"http://1.2.3.4/api/0.1.0/users",
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
		"no body": {
			inReq: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/users", nil),

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode request body: JSON payload is empty"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc: %s", name), func(t *testing.T) {

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("CreateUser", mtesting.ContextMatcher(),
				mock.AnythingOfType("*model.User")).
				Return(tc.createUserErr)

			api := makeMockApiHandler(t, uadm)

			tc.inReq.Header.Add(requestid.RequestIdHeader, "test")
			recorded := test.RunRequest(t, api, tc.inReq)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func makeMockApiHandler(t *testing.T, uadm useradm.App) http.Handler {
	handlers := NewUserAdmApiHandlers(uadm)
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
	privkey, err := keys.LoadRSAPrivate("../../crypto/private.pem")
	if !assert.NoError(t, err) {
		t.Fatalf("faied to load private key: %v", err)
	}

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
		JWTHandler: jwt.NewJWTHandlerRS256(privkey),
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
		t.Logf("test case: %v", name)

		ctx := context.TODO()

		//make mock useradm
		uadm := &museradm.App{}
		uadm.On("Verify", ctx,
			mock.AnythingOfType("*jwt.Token")).
			Return(tc.uaError)

		//make handler
		api := makeMockApiHandler(t, uadm)

		//make request
		req := makeReq("POST",
			"http://1.2.3.4/api/0.1.0/auth/verify",
			"Bearer "+token,
			nil)

		// set these to make the middleware happy
		req.Header.Add("X-Original-URI", "/api/mgmt/0.1/someservice/some/resource")
		req.Header.Add("X-Original-Method", "POST")

		//test
		recorded := test.RunRequest(t, api, req)
		mt.CheckResponse(t, tc.checker, recorded)
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

		checker mt.ResponseChecker
	}{
		"ok": {
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
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {

			ctx := context.TODO()

			//make mock useradm
			uadm := &museradm.App{}
			uadm.On("GetUsers", ctx).Return(tc.uaUsers, tc.uaError)

			//make handler
			api := makeMockApiHandler(t, uadm)

			//make request
			req := makeReq("GET",
				"http://1.2.3.4/api/0.1.0/users",
				"Bearer "+token,
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
