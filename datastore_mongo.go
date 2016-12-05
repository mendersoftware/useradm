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
	"sync"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	DbName      = "useradm"
	DbUsersColl = "users"

	DbUserEmail = "email"
)

var (
	// masterSession is a master session to be copied on demand
	// This is the preferred pattern with mgo (for common conn pool management, etc.)
	masterSession *mgo.Session

	// once ensures mgoMaster is created only once
	once sync.Once
)

type DataStoreMongo struct {
	session *mgo.Session
	log     *log.Logger
}

func GetDataStoreMongo(db string, l *log.Logger) (*DataStoreMongo, error) {
	d, err := NewDataStoreMongo(db)
	if err != nil {
		return nil, errors.Wrap(err, "database connection failed")
	}
	d.UseLog(l)

	return d, nil
}

func NewDataStoreMongoWithSession(session *mgo.Session) (*DataStoreMongo, error) {

	db := &DataStoreMongo{
		session: session,
		log:     log.New(log.Ctx{}),
	}

	err := db.Index()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func NewDataStoreMongo(host string) (*DataStoreMongo, error) {
	//init master session
	var err error
	once.Do(func() {
		masterSession, err = mgo.Dial(host)
	})
	if err != nil {
		return nil, errors.New("failed to open mgo session")
	}

	db, err := NewDataStoreMongoWithSession(masterSession)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DataStoreMongo) IsEmpty() (bool, error) {
	s := db.session.Copy()
	defer s.Close()

	err := s.DB(DbName).C(DbUsersColl).Find(bson.M{}).One(nil)
	if err == mgo.ErrNotFound {
		return true, nil
	}
	return false, err
}

func (db *DataStoreMongo) CreateUser(u *UserModel) error {
	s := db.session.Copy()
	defer s.Close()

	//compute/set password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "failed to generate password hash")
	}
	u.Password = string(hash)

	err = s.DB(DbName).C(DbUsersColl).Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return ErrDuplicateEmail
		}

		return errors.Wrap(err, "failed to insert user")
	}

	return nil
}

func (db *DataStoreMongo) Index() error {
	session := db.session.Copy()
	defer session.Close()

	uniqueEmailIndex := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Name:       "uniqueEmail",
		Background: false,
	}

	return session.DB(DbName).C(DbUsersColl).EnsureIndex(uniqueEmailIndex)
}

func (db *DataStoreMongo) UseLog(l *log.Logger) {
	db.log = l.F(log.Ctx{})
}
