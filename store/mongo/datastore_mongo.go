// Copyright 2021 Northern.tech AS
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
	"strings"
	"time"

	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mopts "go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store"
)

const (
	DbUsersColl    = "users"
	DbTokensColl   = "tokens"
	DbSettingsColl = "settings"

	DbUserEmail   = "email"
	DbUserPass    = "password"
	DbUserLoginTs = "login_ts"

	DbUniqueEmailIndexName = "email_1"
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
	client      *mongo.Client
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

func NewDataStoreMongoWithClient(client *mongo.Client) (*DataStoreMongo, error) {

	db := &DataStoreMongo{
		client: client,
	}

	return db, nil
}

func NewDataStoreMongo(config DataStoreMongoConfig) (*DataStoreMongo, error) {
	var err error
	var mongoURL string

	clientOptions := mopts.Client()
	if !strings.Contains(config.ConnectionString, "://") {
		mongoURL = "mongodb://" + config.ConnectionString
	} else {
		mongoURL = config.ConnectionString

	}
	clientOptions.ApplyURI(mongoURL)

	if config.Username != "" {
		credentials := mopts.Credential{
			Username: config.Username,
		}
		if config.Password != "" {
			credentials.Password = config.Password
			credentials.PasswordSet = true
		}
		clientOptions.SetAuth(credentials)
	}

	if config.SSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.SSLSkipVerify,
		}
		clientOptions.SetTLSConfig(tlsConfig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	// Validate connection
	if err = c.Ping(ctx, nil); err != nil {
		return nil, err
	}

	db, err := NewDataStoreMongoWithClient(c)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DataStoreMongo) Ping(ctx context.Context) error {
	res := db.client.Database(DbName).RunCommand(ctx, bson.M{"ping": 1})
	return res.Err()
}

func (db *DataStoreMongo) CreateUser(ctx context.Context, u *model.User) error {
	now := time.Now().UTC()

	u.CreatedTs = &now
	u.UpdatedTs = &now

	_, err := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl).
		InsertOne(ctx, u)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key error") {
			return store.ErrDuplicateEmail
		}

		return errors.Wrap(err, "failed to insert user")
	}

	return nil
}

func isDuplicateKeyError(err error) bool {
	const errCodeDupKey = 11000
	switch errType := err.(type) {
	case mongo.WriteException:
		if len(errType.WriteErrors) > 0 {
			for _, we := range errType.WriteErrors {
				if we.Code == errCodeDupKey {
					return true
				}
			}
		}
	case mongo.CommandError:
		if errType.Code == errCodeDupKey {
			return true
		}
	}
	return false
}

func (db *DataStoreMongo) UpdateUser(
	ctx context.Context,
	id string,
	u *model.UserUpdate,
) (*model.User, error) {
	var updatedUser = new(model.User)
	//compute/set password hash
	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, errors.Wrap(err,
				"failed to generate password hash")
		}
		u.Password = string(hash)
	}

	now := time.Now().UTC()
	u.UpdatedTs = &now

	collUsers := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl)

	f := bson.M{"_id": id}
	up := bson.M{"$set": u}
	fuOpts := mopts.FindOneAndUpdate().
		SetReturnDocument(mopts.Before)
	err := collUsers.FindOneAndUpdate(ctx, f, up, fuOpts).
		Decode(updatedUser)

	switch {
	case err == mongo.ErrNoDocuments:
		return nil, store.ErrUserNotFound
	case isDuplicateKeyError(err):
		return nil, store.ErrDuplicateEmail
	case err != nil:
		return nil, errors.Wrap(err, "store: failed to update user")
	}

	return updatedUser, nil
}

func (db *DataStoreMongo) UpdateLoginTs(ctx context.Context, id string) error {
	collUsrs := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl)

	_, err := collUsrs.UpdateOne(ctx,
		bson.D{{Key: "_id", Value: id}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: DbUserLoginTs, Value: time.Now()}},
		}},
	)
	return err
}

func (db *DataStoreMongo) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User

	err := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl).
		FindOne(ctx, bson.M{DbUserEmail: email}).
		Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		} else {
			return nil, errors.Wrap(err, "failed to fetch user")
		}
	}

	return &user, nil
}

func (db *DataStoreMongo) GetUserById(ctx context.Context, id string) (*model.User, error) {
	user, err := db.GetUserAndPasswordById(ctx, id)
	if user != nil {
		user.Password = ""
	}
	return user, err
}

func (db *DataStoreMongo) GetUserAndPasswordById(ctx context.Context, id string) (*model.User, error) {
	var user model.User

	err := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl).
		FindOne(ctx, bson.M{"_id": id}).
		Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		} else {
			return nil, errors.Wrap(err, "failed to fetch user")
		}
	}

	return &user, nil
}

func (db *DataStoreMongo) GetTokenById(ctx context.Context, id oid.ObjectID) (*jwt.Token, error) {
	var token jwt.Token

	err := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbTokensColl).
		FindOne(ctx, bson.M{"_id": id}).
		Decode(&token)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		} else {
			return nil, errors.Wrap(err, "failed to fetch token")
		}
	}

	return &token, nil
}

func (db *DataStoreMongo) GetUsers(
	ctx context.Context,
	fltr model.UserFilter,
) ([]model.User, error) {
	findOpts := mopts.Find().
		SetProjection(bson.M{DbUserPass: 0})

	collUsers := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl)

	var mgoFltr = bson.D{}
	if fltr.ID != nil {
		mgoFltr = append(mgoFltr, bson.E{Key: "_id", Value: bson.D{{
			Key: "$in", Value: fltr.ID,
		}}})
	}
	if fltr.Email != nil {
		mgoFltr = append(mgoFltr, bson.E{Key: "email", Value: bson.D{{
			Key: "$in", Value: fltr.Email,
		}}})
	}
	if fltr.CreatedAfter != nil {
		mgoFltr = append(mgoFltr, bson.E{
			Key: "created_ts", Value: bson.D{{
				Key: "$gt", Value: *fltr.CreatedAfter,
			}},
		})
	}
	if fltr.CreatedBefore != nil {
		mgoFltr = append(mgoFltr, bson.E{
			Key: "created_ts", Value: bson.D{{
				Key: "$lt", Value: *fltr.CreatedBefore,
			}},
		})
	}
	if fltr.UpdatedAfter != nil {
		mgoFltr = append(mgoFltr, bson.E{
			Key: "updated_ts", Value: bson.D{{
				Key: "$gt", Value: *fltr.UpdatedAfter,
			}},
		})
	}
	if fltr.UpdatedBefore != nil {
		mgoFltr = append(mgoFltr, bson.E{
			Key: "updated_ts", Value: bson.D{{
				Key: "$lt", Value: *fltr.UpdatedBefore,
			}},
		})
	}
	cur, err := collUsers.Find(ctx, mgoFltr, findOpts)
	if err != nil {
		return nil, errors.Wrap(err, "store: failed to fetch users")
	}

	users := []model.User{}
	err = cur.All(ctx, &users)
	switch err {
	case nil, mongo.ErrNoDocuments:
		return users, nil
	default:
		return nil, errors.Wrap(err, "store: failed to decode users")
	}
}

func (db *DataStoreMongo) DeleteUser(ctx context.Context, id string) error {
	_, err := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbUsersColl).
		DeleteOne(ctx, bson.M{"_id": id})

	if err != nil {
		return err
	}

	return nil
}

func (db *DataStoreMongo) SaveToken(ctx context.Context, token *jwt.Token) error {
	_, err := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbTokensColl).
		InsertOne(ctx, token)

	if err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	return nil
}

// WithMultitenant enables multitenant support and returns a new datastore based
// on current one
func (db *DataStoreMongo) WithMultitenant() *DataStoreMongo {
	return &DataStoreMongo{
		client:      db.client,
		automigrate: db.automigrate,
		multitenant: true,
	}
}

// WithAutomigrate enables automatic migration and returns a new datastore based
// on current one
func (db *DataStoreMongo) WithAutomigrate() *DataStoreMongo {
	return &DataStoreMongo{
		client:      db.client,
		automigrate: true,
		multitenant: db.multitenant,
	}
}

func (db *DataStoreMongo) DeleteToken(ctx context.Context, tokenID oid.ObjectID) error {
	_, err := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbTokensColl).
		DeleteOne(ctx, bson.M{"_id": tokenID})
	return err
}

// deletes all tenant's tokens (identity in context)
func (db *DataStoreMongo) DeleteTokens(ctx context.Context) error {
	d, err := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbTokensColl).
		DeleteMany(ctx, bson.M{})

	if err != nil {
		return err
	}

	if d.DeletedCount == 0 {
		return store.ErrTokenNotFound
	}

	return err
}

// deletes all user's tokens
func (db *DataStoreMongo) DeleteTokensByUserId(ctx context.Context, userId string) error {
	return db.DeleteTokensByUserIdExceptCurrentOne(ctx, userId, oid.ObjectID{})
}

// deletes all user's tokens except the current one
func (db *DataStoreMongo) DeleteTokensByUserIdExceptCurrentOne(ctx context.Context, userId string, tokenID oid.ObjectID) error {
	c := db.client.
		Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbTokensColl)

	id := oid.FromString(userId)
	filter := bson.M{
		"sub": id,
	}

	if tokenID != (oid.ObjectID{}) {
		filter["_id"] = bson.M{
			"$ne": tokenID,
		}
	}

	_, err := c.DeleteMany(ctx, filter)
	if err != nil {
		return errors.Wrap(err, "failed to remove tokens")
	}

	return nil
}

func (db *DataStoreMongo) SaveSettings(ctx context.Context, s map[string]interface{}) error {
	c := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbSettingsColl)

	o := mopts.FindOneAndReplace()
	o.SetUpsert(true)

	var res interface{}
	err := c.FindOneAndReplace(ctx, bson.M{}, s, o).Decode(&res)
	if err != nil && err != mongo.ErrNoDocuments {
		return errors.Wrapf(err, "failed to store settings %v", s)
	}

	return nil
}

func (db *DataStoreMongo) GetSettings(ctx context.Context) (map[string]interface{}, error) {
	c := db.client.Database(mstore.DbFromContext(ctx, DbName)).
		Collection(DbSettingsColl)

	o := mopts.FindOne()
	o.SetProjection(bson.M{"_id": 0})

	var settings map[string]interface{}

	err := c.FindOne(ctx, bson.M{}, o).
		Decode(&settings)

	switch err {
	case nil:
		return settings, nil
	case mongo.ErrNoDocuments:
		return map[string]interface{}{}, nil
	default:
		return nil, errors.Wrapf(err, "failed to get settings")
	}
}
