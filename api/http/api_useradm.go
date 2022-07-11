// Copyright 2022 Northern.tech AS
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
	"net/http"
	"strings"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/google/uuid"
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
	apiUrlManagementV1      = "/api/management/v1/useradm"
	uriManagementAuthLogin  = apiUrlManagementV1 + "/auth/login"
	uriManagementAuthLogout = apiUrlManagementV1 + "/auth/logout"
	uriManagementUser       = apiUrlManagementV1 + "/users/:id"
	uriManagementUsers      = apiUrlManagementV1 + "/users"
	uriManagementSettings   = apiUrlManagementV1 + "/settings"
	uriManagementTokens     = apiUrlManagementV1 + "/settings/tokens"
	uriManagementToken      = apiUrlManagementV1 + "/settings/tokens/:id"

	apiUrlInternalV1  = "/api/internal/v1/useradm"
	uriInternalAlive  = apiUrlInternalV1 + "/alive"
	uriInternalHealth = apiUrlInternalV1 + "/health"

	uriInternalAuthVerify  = apiUrlInternalV1 + "/auth/verify"
	uriInternalTenants     = apiUrlInternalV1 + "/tenants"
	uriInternalTenantUsers = apiUrlInternalV1 + "/tenants/:id/users"
	uriInternalTenantUser  = apiUrlInternalV1 + "/tenants/:id/users/:userid"
	uriInternalTokens      = apiUrlInternalV1 + "/tokens"
)

const (
	defaultTimeout = time.Second * 5
	pathParamMe    = "me"
	hdrETag        = "ETag"
	hdrIfMatch     = "If-Match"
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
	config  Config
}

type Config struct {
	// maximum expiration time for Personal Access Token
	TokenMaxExpSeconds int
}

// return an ApiHandler for user administration and authentiacation app
func NewUserAdmApiHandlers(
	userAdm useradm.App,
	db store.DataStore,
	jwth *jwt.JWTHandlerRS256,
	config Config,
) ApiHandler {
	return &UserAdmApiHandlers{
		userAdm: userAdm,
		db:      db,
		jwth:    jwth,
		config:  config,
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
		rest.Post(uriManagementTokens, i.IssueTokenHandler),
		rest.Get(uriManagementTokens, i.GetTokensHandler),
		rest.Delete(uriManagementToken, i.DeleteTokenHandler),
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
	user, pass, ok := r.BasicAuth()
	if !ok {
		rest_utils.RestErrWithLog(w, r, l,
			ErrAuthHeader, http.StatusUnauthorized)
		return
	}
	email := model.Email(strings.ToLower(user))

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

func getUserIdFromPath(r *rest.Request) string {
	id := r.PathParam("id")
	if id == pathParamMe {
		id = identity.FromContext(r.Context()).Subject
	}
	return id
}

func (u *UserAdmApiHandlers) GetUserHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	id := getUserIdFromPath(r)
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

	id := getUserIdFromPath(r)
	err = u.userAdm.UpdateUser(ctx, id, userUpdate)
	if err != nil {
		switch err {
		case store.ErrDuplicateEmail, store.ErrCurrentPasswordMismatch:
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

	settings := &model.Settings{}
	err := r.DecodeJsonPayload(settings)
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

	if err := settings.Validate(); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	ifMatchHeader := r.Header.Get(hdrIfMatch)

	settings.ETag = uuid.NewString()
	err = u.db.SaveSettings(ctx, settings, ifMatchHeader)
	if err == store.ErrETagMismatch {
		rest_utils.RestErrWithInfoMsg(w, r, l, err, http.StatusPreconditionFailed, err.Error())
		return
	} else if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
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
	} else if settings == nil {
		settings = &model.Settings{
			Values: model.SettingsValues{},
		}
	}

	if settings.ETag != "" {
		w.Header().Set(hdrETag, settings.ETag)
	}
	_ = w.WriteJson(settings)
}

func (u *UserAdmApiHandlers) IssueTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	var tokenRequest model.TokenRequest

	if err := r.DecodeJsonPayload(&tokenRequest); err != nil {
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			errors.New("cannot parse request body as json"),
			http.StatusBadRequest,
		)
		return
	}
	if err := tokenRequest.Validate(u.config.TokenMaxExpSeconds); err != nil {
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			err,
			http.StatusBadRequest,
		)
		return
	}

	token, err := u.userAdm.IssuePersonalAccessToken(ctx, &tokenRequest)
	switch err {
	case nil:
		writer := w.(http.ResponseWriter)
		writer.Header().Set("Content-Type", "application/jwt")
		_, _ = writer.Write([]byte(token))
	case useradm.ErrTooManyTokens:
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			err,
			http.StatusUnprocessableEntity,
		)
	case useradm.ErrDuplicateTokenName:
		rest_utils.RestErrWithLog(
			w,
			r,
			l,
			err,
			http.StatusConflict,
		)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (u *UserAdmApiHandlers) GetTokensHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)
	id := identity.FromContext(ctx)
	if id == nil {
		rest_utils.RestErrWithLogInternal(w, r, l, errors.New("identity not present"))
		return
	}

	tokens, err := u.userAdm.GetPersonalAccessTokens(ctx, id.Subject)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	_ = w.WriteJson(tokens)
}

func (u *UserAdmApiHandlers) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	err := u.userAdm.DeleteToken(ctx, r.PathParam("id"))
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
