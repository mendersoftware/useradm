// Copyright 2020 Northern.tech AS
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

	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mopts "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	OldDbUniqueEmailIndexName = "uniqueEmail"
)

type migration_1_1_4 struct {
	ds  *DataStoreMongo
	ctx context.Context
}

func (m *migration_1_1_4) Up(from migrate.Version) error {
	c := m.ds.client.Database(mstore.DbFromContext(m.ctx, DbName)).
		Collection(DbUsersColl)

	idxUsers := c.Indexes()

	// create new index with predictable name
	indexOptions := mopts.Index()
	indexOptions.SetUnique(true)
	indexOptions.SetBackground(false)
	indexOptions.SetName(DbUniqueEmailIndexName)

	uniqueEmailIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: DbUserEmail, Value: 1}},
		Options: indexOptions,
	}

	_, err := idxUsers.CreateOne(m.ctx, uniqueEmailIndex)
	if err != nil {
		return err
	}

	// drop old index
	_, err = idxUsers.DropOne(m.ctx, OldDbUniqueEmailIndexName)
	if err != nil && err.Error() != "(IndexNotFound) index not found with name [uniqueEmail]" {
		return err
	}

	return nil
}

func (m *migration_1_1_4) Version() migrate.Version {
	return migrate.MakeVersion(1, 1, 4)
}
