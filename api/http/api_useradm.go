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
	"io/ioutil"
	"net/http"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/mendersoftware/go-lib-micro/routing"
	"github.com/pkg/errors"

	"github.com/mendersoftware/useradm/authz"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
	"github.com/mendersoftware/useradm/user"
)

const (
	uriBase       = "/api/0.1.0/"
	uriAuthLogin  = uriBase + "auth/login"
	uriAuthVerify = uriBase + "auth/verify"
	uriUser       = uriBase + "users/:id"
	uriUsers      = uriBase + "users"
)

var (
	ErrAuthHeader = errors.New("invalid or missing auth header")
)

type UserAdmApiHandlers struct {
	userAdm useradm.App
}

// return an ApiHandler for user administration and authentiacation app
func NewUserAdmApiHandlers(userAdm useradm.App) ApiHandler {
	return &UserAdmApiHandlers{
		userAdm: userAdm,
	}
}

func (i *UserAdmApiHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthLogin, i.AuthLoginHandler),
		rest.Post(uriAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriUsers, i.AddUserHandler),
		rest.Get(uriUsers, i.GetUsersHandler),
	}

	routes = append(routes)

	app, err := rest.MakeRouter(
		// augment routes with OPTIONS handler
		routing.AutogenOptionsRoutes(routes, routing.AllowHeaderOptionsGenerator)...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create router")
	}

	return app, nil
}

func (u *UserAdmApiHandlers) AuthLoginHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	//parse auth header
	email, pass, ok := r.BasicAuth()
	if !ok {
		rest_utils.RestErrWithLog(w, r, l,
			ErrAuthHeader, http.StatusUnauthorized)
		return
	}

	token, err := u.userAdm.Login(ctx, email, pass)
	if err != nil {
		switch {
		case err == useradm.ErrUnauthorized:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnauthorized)
		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	raw, err := u.userAdm.SignToken(ctx, token)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.(http.ResponseWriter).Write([]byte(raw))
	w.Header().Set("Content-Type", "application/jwt")
}

func (u *UserAdmApiHandlers) AuthVerifyHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	// note that the request has passed through authz - the token is valid
	token := authz.GetRequestToken(r.Env)

	err := u.userAdm.Verify(ctx, token)
	if err != nil {
		if err == useradm.ErrUnauthorized {
			rest_utils.RestErrWithLog(w, r, l, useradm.ErrUnauthorized, http.StatusUnauthorized)
		} else {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (u *UserAdmApiHandlers) AddUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	user, err := parseUser(r)
	if err != nil {
		if err == model.ErrPasswordTooShort {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		} else {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		}
		return
	}

	err = u.userAdm.CreateUser(ctx, user)
	if err != nil {
		if err == store.ErrDuplicateEmail {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		} else {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	w.Header().Add("Location", "users/"+string(user.ID))
	w.WriteHeader(http.StatusCreated)

}

func (u *UserAdmApiHandlers) GetUsersHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	users, err := u.userAdm.GetUsers(ctx)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(users)
}

func parseUser(r *rest.Request) (*model.User, error) {
	user := model.User{}

	//decode body
	err := r.DecodeJsonPayload(&user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode request body")
	}

	if err := user.ValidateNew(); err != nil {
		return nil, err
	}

	return &user, nil
}

func readBodyRaw(r *rest.Request) ([]byte, error) {
	content, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}

	return content, nil
}
