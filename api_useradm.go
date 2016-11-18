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
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/routing"
	"github.com/pkg/errors"
)

const (
	uriAuthLogin    = "/api/0.1.0/auth/login"
	uriAuthVerify   = "/api/0.1.0/auth/verify"
	uriUsersInitial = "/api/0.1.0/users/initial"
)

type UserAdmHandlers struct {
}

// return an ApiHandler for user administration and authentiacation app
func NewUserAdmApiHandlers() ApiHandler {
	return &UserAdmHandlers{}
}

func (i *UserAdmHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthLogin, i.AuthLoginHandler),
		rest.Post(uriAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriUsersInitial, i.PostUsersInitialHandler),
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

func (i *UserAdmHandlers) AuthLoginHandler(w rest.ResponseWriter, r *rest.Request) {
	rest.NotFound(w, r)
}

func (i *UserAdmHandlers) AuthVerifyHandler(w rest.ResponseWriter, r *rest.Request) {
	rest.NotFound(w, r)
}

func (i *UserAdmHandlers) PostUsersInitialHandler(w rest.ResponseWriter, r *rest.Request) {
	rest.NotFound(w, r)
}
