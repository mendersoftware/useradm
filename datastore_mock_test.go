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
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/stretchr/testify/mock"
)

type mockDataStore struct {
	mock.Mock
}

func (m *mockDataStore) IsEmpty() (bool, error) {
	ret := m.Called()
	return ret.Get(0).(bool), ret.Error(1)
}

// CreateUser provides a mock function with given fields: u
func (_m *mockDataStore) CreateUser(u *UserModel) error {
	ret := _m.Called(u)

	var r0 error
	if rf, ok := ret.Get(0).(func(*UserModel) error); ok {
		r0 = rf(u)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetUserByEmail provides a mock function with given fields: email
func (m *mockDataStore) GetUserByEmail(email string) (*UserModel, error) {
	ret := m.Called(email)

	var r0 *UserModel
	if rf, ok := ret.Get(0).(func(string) *UserModel); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserModel)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func (m *mockDataStore) GetUserById(id string) (*UserModel, error) {
	ret := m.Called(id)

	var r0 *UserModel
	if rf, ok := ret.Get(0).(func(string) *UserModel); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserModel)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UseLog provides a mock function with given fields: l
func (m *mockDataStore) UseLog(l *log.Logger) {
	m.Called(l)
}
