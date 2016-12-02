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
	"errors"

	"github.com/mendersoftware/go-lib-micro/log"
)

var (
	// device not found
	ErrDevNotFound = errors.New("device not found")
	// device not found
	ErrTokenNotFound = errors.New("token not found")
)

type DataStore interface {
	// IsEmpty returns true if database is empty (i.e. clean state of the
	// system)
	IsEmpty() (bool, error)
	log.ContextLogger
}
