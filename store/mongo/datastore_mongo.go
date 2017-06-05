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

package mongo

import (
	"context"
	"sync"
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
)

const (
	DbVersion   = "0.1.0"
	DbName      = "useradm"
	DbUsersColl = "users"

	DbUserEmail = "email"
	DbUserPass  = "password"
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
}

func GetDataStoreMongo(db string) (*DataStoreMongo, error) {
	d, err := NewDataStoreMongo(db)
	if err != nil {
		return nil, errors.Wrap(err, "database connection failed")
	}
	return d, nil
}

func NewDataStoreMongoWithSession(session *mgo.Session) (*DataStoreMongo, error) {

	db := &DataStoreMongo{
		session: session,
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

		if err == nil {
			// force write ack with immediate journal file fsync
			masterSession.SetSafe(&mgo.Safe{
				W: 1,
				J: true,
			})
		}
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

func (db *DataStoreMongo) CreateUser(ctx context.Context, u *model.User) error {
	s := db.session.Copy()
	defer s.Close()

	now := time.Now().UTC()

	//compute/set password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "failed to generate password hash")
	}
	u.Password = string(hash)

	u.CreatedTs = &now
	u.UpdatedTs = &now

	err = s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return store.ErrDuplicateEmail
		}

		return errors.Wrap(err, "failed to insert user")
	}

	return nil
}

func (db *DataStoreMongo) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	s := db.session.Copy()
	defer s.Close()

	var user model.User

	err := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).Find(bson.M{DbUserEmail: email}).One(&user)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		} else {
			return nil, errors.Wrap(err, "failed to fetch user")
		}
	}

	return &user, nil
}

func (db *DataStoreMongo) GetUserById(ctx context.Context, id string) (*model.User, error) {
	s := db.session.Copy()
	defer s.Close()

	var user model.User

	err := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).FindId(id).One(&user)

	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, nil
		} else {
			return nil, errors.Wrap(err, "failed to fetch user")
		}
	}

	return &user, nil
}

func (db *DataStoreMongo) GetUsers(ctx context.Context) ([]model.User, error) {
	s := db.session.Copy()
	defer s.Close()

	users := []model.User{}

	err := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).
		Find(nil).
		Select(bson.M{DbUserPass: 0}).
		All(&users)

	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch users")
	}

	return users, nil
}

func (db *DataStoreMongo) Migrate(ctx context.Context, version string, migrations []migrate.Migration) error {
	m := migrate.DummyMigrator{
		Session: db.session,
		Db:      mstore.DbFromContext(ctx, DbName),
	}

	ver, err := migrate.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "failed to parse service version")
	}

	err = m.Apply(ctx, *ver, migrations)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
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
