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

package mongo

import (
	"context"
	"errors"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	"go.mongodb.org/mongo-driver/bson"
)

type migration_2_0_2 struct {
	ds     *DataStoreMongo
	dbName string
	ctx    context.Context
}

func (m *migration_2_0_2) Up(from migrate.Version) error {
	logger := log.FromContext(m.ctx)
	ctx := context.Background()

	// after the move to single tenant we apply the migrations on ly to one db
	if m.dbName == DbName {
		usersCollection := m.ds.client.Database(m.dbName).Collection(DbUsersColl)
		result, err := usersCollection.UpdateMany(
			ctx,
			bson.M{
				"login": bson.M{"$exists": true},
			},
			bson.M{
				"$set": bson.M{DbIsOauthUser: true},
			},
		)
		if err != nil {
			return err
		}

		if result == nil {
			return errors.New("nil result on update")
		}

		logger.Infof("updated %d documents in %s.", result.ModifiedCount, DbUsersColl)
	}

	return nil
}

func (m *migration_2_0_2) Version() migrate.Version {
	return migrate.MakeVersion(2, 0, 2)
}
