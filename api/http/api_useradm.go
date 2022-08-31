// Copyright 2022 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package http

import (
	"context"
	"net/http"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/mendersoftware/go-lib-micro/routing"
	"github.com/pkg/errors"

	"github.com/mendersoftware/useradm/authz"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
	useradm "github.com/mendersoftware/useradm/user"
)

const (
	uriManagementAuthLogin  = "/api/management/v1/useradm/auth/login"
	uriManagementAuthLogout = "/api/management/v1/useradm/auth/logout"
	uriManagementUser       = "/api/management/v1/useradm/users/#id"
	uriManagementUsers      = "/api/management/v1/useradm/users"
	uriManagementSettings   = "/api/management/v1/useradm/settings"

	uriInternalAlive  = "/api/internal/v1/useradm/alive"
	uriInternalHealth = "/api/internal/v1/useradm/health"

	uriInternalAuthVerify  = "/api/internal/v1/useradm/auth/verify"
	uriInternalTenants     = "/api/internal/v1/useradm/tenants"
	uriInternalTenantUsers = "/api/internal/v1/useradm/tenants/#id/users"
	uriInternalTenantUser  = "/api/internal/v1/useradm/tenants/#id/users/#userid"
	uriInternalTokens      = "/api/internal/v1/useradm/tokens"
)

const (
	defaultTimeout = time.Second * 5
)

const (
	uriUIRoot = "/"
)

var (
	ErrAuthHeader   = errors.New("invalid or missing auth header")
	ErrUserNotFound = errors.New("user not found")
)

type UserAdmApiHandlers struct {
	userAdm useradm.App
	db      store.DataStore
	jwth    *jwt.JWTHandlerRS256
}

// return an ApiHandler for user administration and authentiacation app
func NewUserAdmApiHandlers(
	userAdm useradm.App,
	db store.DataStore,
	jwth *jwt.JWTHandlerRS256,
) ApiHandler {
	return &UserAdmApiHandlers{
		userAdm: userAdm,
		db:      db,
		jwth:    jwth,
	}
}

func (i *UserAdmApiHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Get(uriInternalAlive, i.AliveHandler),
		rest.Get(uriInternalHealth, i.HealthHandler),

		rest.Get(uriInternalAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriInternalAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriInternalTenants, i.CreateTenantHandler),
		rest.Post(uriInternalTenantUsers, i.CreateTenantUserHandler),
		rest.Delete(uriInternalTenantUser, i.DeleteTenantUserHandler),
		rest.Get(uriInternalTenantUsers, i.GetTenantUsersHandler),
		rest.Delete(uriInternalTokens, i.DeleteTokensHandler),

		rest.Post(uriManagementAuthLogin, i.AuthLoginHandler),
		rest.Post(uriManagementAuthLogout, i.AuthLogoutHandler),
		rest.Post(uriManagementUsers, i.AddUserHandler),
		rest.Get(uriManagementUsers, i.GetUsersHandler),
		rest.Get(uriManagementUser, i.GetUserHandler),
		rest.Put(uriManagementUser, i.UpdateUserHandler),
		rest.Delete(uriManagementUser, i.DeleteUserHandler),
		rest.Post(uriManagementSettings, i.SaveSettingsHandler),
		rest.Get(uriManagementSettings, i.GetSettingsHandler),
	}

	app, err := rest.MakeRouter(
		// augment routes with OPTIONS handler
		routing.AutogenOptionsRoutes(routes, routing.AllowHeaderOptionsGenerator)...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create router")
	}

	return app, nil
}

func (u *UserAdmApiHandlers) AliveHandler(w rest.ResponseWriter, r *rest.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (u *UserAdmApiHandlers) HealthHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	err := u.userAdm.HealthCheck(ctx)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		case err == useradm.ErrUnauthorized || err == useradm.ErrTenantAccountSuspended:
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

	writer := w.(http.ResponseWriter)
	writer.Header().Set("Content-Type", "application/jwt")
	http.SetCookie(writer, &http.Cookie{
		Name:     "JWT",
		Value:    raw,
		Path:     uriUIRoot,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		Expires:  token.ExpiresAt.Time,
	})
	_, _ = writer.Write([]byte(raw))
}

func (u *UserAdmApiHandlers) AuthLogoutHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	if tokenStr, err := authz.ExtractToken(r.Request); err == nil {
		token, err := u.jwth.FromJWT(tokenStr)
		if err != nil {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
			return
		}
		if err := u.userAdm.Logout(ctx, token); err != nil {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
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

func (u *UserAdmApiHandlers) CreateTenantUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	user, err := parseUserInternal(r)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	tenantId := r.PathParam("id")
	if tenantId == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("Entity not found"), http.StatusNotFound)
		return
	}
	ctx = getTenantContext(ctx, tenantId)
	err = u.userAdm.CreateUserInternal(ctx, user)
	if err != nil {
		if err == store.ErrDuplicateEmail {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		} else {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)

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

	if err := r.ParseForm(); err != nil {
		err = errors.Wrap(err, "api: bad form parameters")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	fltr := model.UserFilter{}
	if err := fltr.ParseForm(r.Form); err != nil {
		err = errors.Wrap(err, "api: invalid form values")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	users, err := u.userAdm.GetUsers(ctx, fltr)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	_ = w.WriteJson(users)
}

func (u *UserAdmApiHandlers) GetTenantUsersHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: r.PathParam("id"),
	})
	r.Request = r.Request.WithContext(ctx)
	u.GetUsersHandler(w, r)
}

func (u *UserAdmApiHandlers) GetUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	id := r.PathParam("id")
	user, err := u.userAdm.GetUser(ctx, id)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	if user == nil {
		rest_utils.RestErrWithLog(w, r, l, ErrUserNotFound, 404)
		return
	}

	_ = w.WriteJson(user)
}

func (u *UserAdmApiHandlers) UpdateUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	userUpdate, err := parseUserUpdate(r)
	if err != nil {
		if err == model.ErrPasswordTooShort {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		} else {
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		}
		return
	}

	// extract the token used to update the user
	if tokenStr, err := authz.ExtractToken(r.Request); err == nil {
		token, err := u.jwth.FromJWT(tokenStr)
		if err != nil {
			rest_utils.RestErrWithLogInternal(w, r, l, err)
			return
		}
		userUpdate.Token = token
	}

	id := r.PathParam("id")
	err = u.userAdm.UpdateUser(ctx, id, userUpdate)
	if err != nil {
		switch err {
		case store.ErrDuplicateEmail,
			useradm.ErrCurrentPasswordMismatch,
			useradm.ErrCannotModifyPassword:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
		case store.ErrUserNotFound:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (u *UserAdmApiHandlers) DeleteTenantUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	tenantId := r.PathParam("id")
	if tenantId != "" {
		ctx = getTenantContext(ctx, tenantId)
	}

	l := log.FromContext(ctx)
	err := u.userAdm.DeleteUser(ctx, r.PathParam("userid"))
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
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

	if err := user.Validate(); err != nil {
		return nil, err
	}

	return &user, nil
}

func parseUserInternal(r *rest.Request) (*model.UserInternal, error) {
	user := model.UserInternal{}

	//decode body
	err := r.DecodeJsonPayload(&user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode request body")
	}

	if err := user.Validate(); err != nil {
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

func (u *UserAdmApiHandlers) CreateTenantHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	var newTenant model.NewTenant

	if err := r.DecodeJsonPayload(&newTenant); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if err := newTenant.Validate(); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err := u.userAdm.CreateTenant(ctx, model.NewTenant{
		ID: newTenant.ID,
	})
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func getTenantContext(ctx context.Context, tenantId string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if tenantId != "" {
		id := &identity.Identity{
			Tenant: tenantId,
		}

		ctx = identity.WithContext(ctx, id)
	}

	return ctx
}

func (u *UserAdmApiHandlers) DeleteTokensHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	tenantId := r.URL.Query().Get("tenant_id")
	if tenantId == "" {
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			errors.New("tenant_id must be provided"),
			http.StatusBadRequest,
		)
		return
	}
	userId := r.URL.Query().Get("user_id")

	err := u.userAdm.DeleteTokens(ctx, tenantId, userId)
	switch err {
	case nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (u *UserAdmApiHandlers) SaveSettingsHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	var settings map[string]interface{}

	err := r.DecodeJsonPayload(&settings)
	if err != nil {
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			errors.New("cannot parse request body as json"),
			http.StatusBadRequest,
		)
		return
	}

	err = u.db.SaveSettings(ctx, settings)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}

	w.WriteHeader(http.StatusCreated)
}

func (u *UserAdmApiHandlers) GetSettingsHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	settings, err := u.db.GetSettings(ctx)

	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	_ = w.WriteJson(settings)
}
