// Copyright 2017 Northern.tech AS
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
	"github.com/asaskevich/govalidator"
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
	uriManagementAuthLogin = "/api/management/v1/useradm/auth/login"
	uriManagementUser      = "/api/management/v1/useradm/users/:id"
	uriManagementUsers     = "/api/management/v1/useradm/users"

	uriInternalAuthVerify = "/api/internal/v1/useradm/auth/verify"
	uriInternalTenants    = "/api/internal/v1/useradm/tenants"
)

var (
	ErrAuthHeader   = errors.New("invalid or missing auth header")
	ErrUserNotFound = errors.New("user not found")
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
		rest.Post(uriInternalAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriInternalTenants, i.CreateTenantHandler),

		rest.Post(uriManagementAuthLogin, i.AuthLoginHandler),
		rest.Post(uriManagementUsers, i.AddUserHandler),
		rest.Get(uriManagementUsers, i.GetUsersHandler),
		rest.Get(uriManagementUser, i.GetUserHandler),
		rest.Put(uriManagementUser, i.UpdateUserHandler),
		rest.Delete(uriManagementUser, i.DeleteUserHandler),
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

	w.Header().Set("Content-Type", "application/jwt")
	w.(http.ResponseWriter).Write([]byte(raw))
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

func (u *UserAdmApiHandlers) GetUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	user, err := u.userAdm.GetUser(ctx, r.PathParam("id"))
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	if user == nil {
		rest_utils.RestErrWithLog(w, r, l, ErrUserNotFound, 404)
		return
	}

	w.WriteJson(user)
}

func (u *UserAdmApiHandlers) UpdateUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	id := r.PathParam("id")

	userUpdate, err := parseUserUpdate(r)
	if err != nil {
		if err == model.ErrPasswordTooShort {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		} else {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		}
		return
	}

	err = u.userAdm.UpdateUser(ctx, id, userUpdate)
	if err != nil {
		switch err {
		case store.ErrDuplicateEmail:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		case store.ErrUserNotFound:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (u *UserAdmApiHandlers) DeleteUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	err := u.userAdm.DeleteUser(ctx, r.PathParam("id"))
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

func parseUserUpdate(r *rest.Request) (*model.UserUpdate, error) {
	userUpdate := model.UserUpdate{}

	//decode body
	err := r.DecodeJsonPayload(&userUpdate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode request body")
	}

	if err := userUpdate.Validate(); err != nil {
		return nil, err
	}

	return &userUpdate, nil
}

func readBodyRaw(r *rest.Request) ([]byte, error) {
	content, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}

	return content, nil
}

type newTenantRequest struct {
	TenantID string `json:"tenant_id" valid:"required"`
}

func (u *UserAdmApiHandlers) CreateTenantHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	var newTenant newTenantRequest

	if err := r.DecodeJsonPayload(&newTenant); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if _, err := govalidator.ValidateStruct(newTenant); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err := u.userAdm.CreateTenant(ctx, model.NewTenant{
		ID: newTenant.TenantID,
	})
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
