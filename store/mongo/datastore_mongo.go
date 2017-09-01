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

package mongo

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/mendersoftware/go-lib-micro/log"
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

type DataStoreMongoConfig struct {
	// MGO connection string
	ConnectionString string

	// SSL support
	SSL           bool
	SSLSkipVerify bool

	// Overwrites credentials provided in connection string if provided
	Username string
	Password string
}

type DataStoreMongo struct {
	session     *mgo.Session
	automigrate bool
	multitenant bool
}

func GetDataStoreMongo(config DataStoreMongoConfig) (*DataStoreMongo, error) {
	d, err := NewDataStoreMongo(config)
	if err != nil {
		return nil, errors.Wrap(err, "database connection failed")
	}
	return d, nil
}

func NewDataStoreMongoWithSession(session *mgo.Session) (*DataStoreMongo, error) {

	db := &DataStoreMongo{
		session: session,
	}

	return db, nil
}

// NewDataStoreMongo expects mongodb connection url.
func NewDataStoreMongo(config DataStoreMongoConfig) (*DataStoreMongo, error) {
	//init master session
	var err error
	once.Do(func() {

		var dialInfo *mgo.DialInfo
		dialInfo, err = mgo.ParseURL(config.ConnectionString)
		if err != nil {
			return
		}

		// Set 10s timeout - same as set by Dial
		dialInfo.Timeout = 10 * time.Second

		if config.Username != "" {
			dialInfo.Username = config.Username
		}
		if config.Password != "" {
			dialInfo.Password = config.Password
		}

		if config.SSL {
			dialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {

				// Setup TLS
				tlsConfig := &tls.Config{}
				tlsConfig.InsecureSkipVerify = config.SSLSkipVerify

				conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
				return conn, err
			}
		}

		masterSession, err = mgo.DialWithInfo(dialInfo)
		if err != nil {
			return
		}

		// Validate connection
		if err = masterSession.Ping(); err != nil {
			return
		}

		// force write ack with immediate journal file fsync
		masterSession.SetSafe(&mgo.Safe{
			W: 1,
			J: true,
		})
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to open mgo session")
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

	if err := db.EnsureIndexes(ctx, s); err != nil {
		return err
	}

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

func (db *DataStoreMongo) UpdateUser(ctx context.Context, id string, u *model.UserUpdate) error {
	s := db.session.Copy()
	defer s.Close()

	//compute/set password hash
	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return errors.Wrap(err, "failed to generate password hash")
		}
		u.Password = string(hash)
	}

	now := time.Now().UTC()
	u.UpdatedTs = &now

	c := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl)
	err := c.UpdateId(id, bson.M{"$set": u})
	if err != nil {
		if err == mgo.ErrNotFound {
			return store.ErrUserNotFound
		}
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

	err := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).
		FindId(id).
		Select(bson.M{DbUserPass: 0}).
		One(&user)

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

func (db *DataStoreMongo) DeleteUser(ctx context.Context, id string) error {
	s := db.session.Copy()
	defer s.Close()

	err := s.DB(mstore.DbFromContext(ctx, DbName)).C(DbUsersColl).RemoveId(id)

	switch err {
	case nil, mgo.ErrNotFound:
		return nil
	default:
		return err
	}
}

func (db *DataStoreMongo) Migrate(ctx context.Context, version string, migrations []migrate.Migration) error {
	l := log.FromContext(ctx)

	dbs := []string{DbName}

	if db.multitenant {
		l.Infof("running migrations in multitenant mode")

		tdbs, err := migrate.GetTenantDbs(db.session, mstore.IsTenantDb(DbName))
		if err != nil {
			return errors.Wrap(err, "failed go retrieve tenant DBs")
		}
		dbs = tdbs
	} else {
		l.Infof("running migrations in single tenant mode")
	}

	if db.automigrate {
		l.Infof("automigrate is ON, will apply migrations")
	} else {
		l.Infof("automigrate is OFF, will check db version compatibility")
	}

	for _, d := range dbs {
		l.Infof("migrating %s", d)
		m := migrate.DummyMigrator{
			Session:     db.session,
			Db:          d,
			Automigrate: db.automigrate,
		}

		ver, err := migrate.NewVersion(version)
		if err != nil {
			return errors.Wrap(err, "failed to parse service version")
		}

		err = m.Apply(ctx, *ver, nil)
		if err != nil {
			return errors.Wrap(err, "failed to apply migrations")
		}
	}

	return nil
}

func (db *DataStoreMongo) EnsureIndexes(ctx context.Context, s *mgo.Session) error {

	uniqueEmailIndex := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Name:       "uniqueEmail",
		Background: false,
	}

	return s.DB(mstore.DbFromContext(ctx, DbName)).
		C(DbUsersColl).EnsureIndex(uniqueEmailIndex)
}

func (db *DataStoreMongo) WithMultitenant() *DataStoreMongo {
	db.multitenant = true
	return db
}

func (db *DataStoreMongo) WithAutomigrate() *DataStoreMongo {
	db.automigrate = true
	return db
}
