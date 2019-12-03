// Copyright 2019 Northern.tech AS
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
package authz_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	mt "github.com/mendersoftware/go-lib-micro/testing"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	. "github.com/mendersoftware/useradm/authz"
	mauthz "github.com/mendersoftware/useradm/authz/mocks"
	"github.com/mendersoftware/useradm/jwt"
	mtest "github.com/mendersoftware/useradm/utils/testing"
)

func TestAuthzMiddleware(t *testing.T) {

	testCases := map[string]struct {
		token string

		action    *Action
		actionErr error

		authErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjQxMDExMDQwNjksImlzcyI6Im1lb" +
				"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
				"NwIjoibWVuZGVyLmZvbyJ9.I6av5-kQdw5iBT" +
				"gZmOs4iBzfVRbdWWmGPfQCoI7CpPcXmQhtRNw" +
				"05kbueWnpZbpPvniu-AfU6fURFWcCN5Xa_fNY" +
				"iuQhYABAAu3SHjfURrmaobr-I4G3MdXT1M-NH" +
				"k1z64uTr8fvQeRePvvYQyLXp6PHVzpHjbPvy4" +
				"9FapKzbG6bWPlRy9AeFaL6bksC2ov9g9iJsaW" +
				"fWUIC-iqAKe7JePtlWK9GS8bzcNraJE6QG1eT" +
				"ifQbf3I25dyjkOFy3yRaGNSpPCo-AYGtF6qOA" +
				"7fQk9deTbWo2KNeXvLKz9TptghF2V5GRsNrig" +
				"vEGfcnVpexPZsx7edgsN_J2XPJV1crRQ",
			action: &Action{
				Resource: "foo:bar",
				Method:   "GET",
			},

			actionErr: nil,

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				map[string]string{"foo": "bar"},
			),
		},

		"error: missing token header": {
			token: "",
			action: &Action{
				Resource: "foo:bar",
				Method:   "GET",
			},

			actionErr: nil,

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("missing or invalid auth header"),
			),
		},

		"error: resource id error": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjQxMDExMDQwNjksImlzcyI6Im1lb" +
				"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
				"NwIjoibWVuZGVyLmZvbyJ9.I6av5-kQdw5iBT" +
				"gZmOs4iBzfVRbdWWmGPfQCoI7CpPcXmQhtRNw" +
				"05kbueWnpZbpPvniu-AfU6fURFWcCN5Xa_fNY" +
				"iuQhYABAAu3SHjfURrmaobr-I4G3MdXT1M-NH" +
				"k1z64uTr8fvQeRePvvYQyLXp6PHVzpHjbPvy4" +
				"9FapKzbG6bWPlRy9AeFaL6bksC2ov9g9iJsaW" +
				"fWUIC-iqAKe7JePtlWK9GS8bzcNraJE6QG1eT" +
				"ifQbf3I25dyjkOFy3yRaGNSpPCo-AYGtF6qOA" +
				"7fQk9deTbWo2KNeXvLKz9TptghF2V5GRsNrig" +
				"vEGfcnVpexPZsx7edgsN_J2XPJV1crRQ",
			action: &Action{
				Resource: "",
				Method:   "GET",
			},
			actionErr: errors.New("can't identify resource"),

			authErr: nil,

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
		"error: invalid token": {
			token: "dummy",
			action: &Action{
				Resource: "foo:bar",
				Method:   "GET",
			},
			actionErr: errors.New("can't identify resource"),

			authErr: ErrAuthzTokenInvalid,

			checker: mt.NewJSONResponse(
				http.StatusUnauthorized,
				nil,
				restError("invalid jwt"),
			),
		},
		"error: unauthorized token": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjQxMDExMDQwNjksImlzcyI6Im1lb" +
				"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
				"NwIjoibWVuZGVyLmZvbyJ9.I6av5-kQdw5iBT" +
				"gZmOs4iBzfVRbdWWmGPfQCoI7CpPcXmQhtRNw" +
				"05kbueWnpZbpPvniu-AfU6fURFWcCN5Xa_fNY" +
				"iuQhYABAAu3SHjfURrmaobr-I4G3MdXT1M-NH" +
				"k1z64uTr8fvQeRePvvYQyLXp6PHVzpHjbPvy4" +
				"9FapKzbG6bWPlRy9AeFaL6bksC2ov9g9iJsaW" +
				"fWUIC-iqAKe7JePtlWK9GS8bzcNraJE6QG1eT" +
				"ifQbf3I25dyjkOFy3yRaGNSpPCo-AYGtF6qOA" +
				"7fQk9deTbWo2KNeXvLKz9TptghF2V5GRsNrig" +
				"vEGfcnVpexPZsx7edgsN_J2XPJV1crRQ",
			action: &Action{
				Resource: "foo:bar",
				Method:   "GET",
			},
			actionErr: nil,

			authErr: ErrAuthzUnauthorized,

			checker: mt.NewJSONResponse(
				http.StatusForbidden,
				nil,
				restError("unauthorized"),
			),
		},
		"error: authorizer internal error": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjQxMDExMDQwNjksImlzcyI6Im1lb" +
				"mRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiwic2" +
				"NwIjoibWVuZGVyLmZvbyJ9.I6av5-kQdw5iBT" +
				"gZmOs4iBzfVRbdWWmGPfQCoI7CpPcXmQhtRNw" +
				"05kbueWnpZbpPvniu-AfU6fURFWcCN5Xa_fNY" +
				"iuQhYABAAu3SHjfURrmaobr-I4G3MdXT1M-NH" +
				"k1z64uTr8fvQeRePvvYQyLXp6PHVzpHjbPvy4" +
				"9FapKzbG6bWPlRy9AeFaL6bksC2ov9g9iJsaW" +
				"fWUIC-iqAKe7JePtlWK9GS8bzcNraJE6QG1eT" +
				"ifQbf3I25dyjkOFy3yRaGNSpPCo-AYGtF6qOA" +
				"7fQk9deTbWo2KNeXvLKz9TptghF2V5GRsNrig" +
				"vEGfcnVpexPZsx7edgsN_J2XPJV1crRQ",
			action: &Action{
				Resource: "foo:bar",
				Method:   "GET",
			},
			actionErr: nil,

			authErr: errors.New("some internal error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error"),
			),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %v", name)

		//setup api
		api := rest.NewApi()
		api.Use(
			&requestlog.RequestLogMiddleware{
				BaseLogger: &logrus.Logger{Out: ioutil.Discard},
			},
			&requestid.RequestIdMiddleware{},
		)
		rest.ErrorFieldName = "error"

		ctx := mtest.ContextMatcher()

		//setup mocks
		a := &mauthz.Authorizer{}
		a.On("Authorize",
			ctx,
			mock.AnythingOfType("*jwt.Token"),
			tc.action.Resource,
			tc.action.Method).Return(tc.authErr)

		a.On("WithLog",
			mock.AnythingOfType("*log.Logger")).
			Return(a)

		resfunc := func(r *rest.Request) (*Action, error) {
			return tc.action, tc.actionErr
		}

		//finish setting up the middleware
		privkey := loadPrivKey("../crypto/private.pem", t)
		jwth := jwt.NewJWTHandlerRS256(privkey)
		mw := AuthzMiddleware{
			Authz:      a,
			ResFunc:    resfunc,
			JWTHandler: jwth,
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

		req := makeReq(tc.action.Method,
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

func loadPrivKey(path string, t *testing.T) *rsa.PrivateKey {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.FailNow()
	}

	block, _ := pem.Decode(pem_data)

	if block == nil ||
		block.Type != "RSA PRIVATE KEY" {
		t.FailNow()
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.FailNow()
	}

	return key
}

func TestGetRequestToken(t *testing.T) {
	token := &jwt.Token{
		Claims: jwt.Claims{
			Subject:   "foo",
			Issuer:    "bar",
			ExpiresAt: 12345,
		},
	}

	env := map[string]interface{}{
		"authz_token": token,
	}

	outToken := GetRequestToken(env)
	assert.Equal(t, token, outToken)

}
