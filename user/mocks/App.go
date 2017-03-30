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
package mocks

import jwt "github.com/mendersoftware/useradm/jwt"
import mock "github.com/stretchr/testify/mock"
import model "github.com/mendersoftware/useradm/model"
import useradm "github.com/mendersoftware/useradm/user"

// App is an autogenerated mock type for the App type
type App struct {
	mock.Mock
}

// CreateUser provides a mock function with given fields: u
func (_m *App) CreateUser(u *model.User) error {
	ret := _m.Called(u)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User) error); ok {
		r0 = rf(u)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUserInitial provides a mock function with given fields: u
func (_m *App) CreateUserInitial(u *model.User) error {
	ret := _m.Called(u)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User) error); ok {
		r0 = rf(u)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Login provides a mock function with given fields: email, pass
func (_m *App) Login(email string, pass string) (*jwt.Token, error) {
	ret := _m.Called(email, pass)

	var r0 *jwt.Token
	if rf, ok := ret.Get(0).(func(string, string) *jwt.Token); ok {
		r0 = rf(email, pass)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*jwt.Token)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(email, pass)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SignToken provides a mock function with given fields:
func (_m *App) SignToken() jwt.SignFunc {
	ret := _m.Called()

	var r0 jwt.SignFunc
	if rf, ok := ret.Get(0).(func() jwt.SignFunc); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(jwt.SignFunc)
		}
	}

	return r0
}

// Verify provides a mock function with given fields: token
func (_m *App) Verify(token *jwt.Token) error {
	ret := _m.Called(token)

	var r0 error
	if rf, ok := ret.Get(0).(func(*jwt.Token) error); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

var _ useradm.App = (*App)(nil)
