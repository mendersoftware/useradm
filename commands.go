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
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/mendersoftware/useradm/client/tenant"
	"github.com/mendersoftware/useradm/model"
	"github.com/mendersoftware/useradm/store/mongo"
	"github.com/mendersoftware/useradm/user"
)

// safeReadPassword reads a user password from a terminal in a safe way (without
// echoing the characters input by the user)
func safeReadPassword() (string, error) {
	stdinfd := int(os.Stdin.Fd())

	if !terminal.IsTerminal(stdinfd) {
		return "", errors.New("stdin is not a terminal")
	}

	fmt.Fprintf(os.Stderr, "Enter password: ")
	raw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", errors.Wrap(err, "failed to read password")
	}
	fmt.Fprintf(os.Stderr, "\n")

	return string(raw), nil
}

func commandCreateUser(c config.Reader, username, password, userId, tenantId string) error {
	l := log.NewEmpty()

	l.Debugf("create user '%s'", username)

	if password == "" {
		var err error
		if password, err = safeReadPassword(); err != nil {
			return err
		}
	}

	u := model.User{
		Email:    username,
		Password: password,
	}

	if userId != "" {
		u.ID = userId
	}

	if err := u.ValidateNew(); err != nil {
		return errors.Wrap(err, "user validation failed")
	}

	db, err := mongo.GetDataStoreMongo(dataStoreMongoConfigFromAppConfig(c))
	if err != nil {
		return errors.Wrap(err, "database connection failed")
	}

	ua := useradm.NewUserAdm(nil, db, mongo.NewTenantStoreMongo(db),
		useradm.Config{})
	if tadmAddr := c.GetString(SettingTenantAdmAddr); tadmAddr != "" {
		l.Infof("setting up tenant verification")

		tc := tenant.NewClient(tenant.Config{
			TenantAdmAddr: tadmAddr,
		})

		ua = ua.WithTenantVerification(tc)
	}

	ctx := getTenantContext(tenantId)
	if err := ua.CreateUser(ctx, &u); err != nil {
		return errors.Wrap(err, "creating user failed")
	}

	fmt.Printf("%s\n", u.ID)

	return nil
}

func getTenantContext(tenantId string) context.Context {
	ctx := context.Background()
	if tenantId != "" {
		id := &identity.Identity{
			Tenant: tenantId,
		}

		ctx = identity.WithContext(ctx, id)
	}

	return ctx
}

func commandMigrate(c config.Reader, tenantId string) error {
	l := log.New(log.Ctx{})

	l.Printf("User Administration Service, version %s starting up",
		CreateVersionString())

	if tenantId != "" {
		l.Printf("migrating tenant %v", tenantId)
	} else {
		l.Printf("migrating all the tenants")
	}

	db, err := mongo.NewDataStoreMongo(dataStoreMongoConfigFromAppConfig(c))

	if err != nil {
		return errors.Wrap(err, "database connection failed")
	}

	// we want to apply migrations
	db = db.WithAutomigrate()

	ctx := context.Background()

	if tenantId != "" {
		err = db.MigrateTenant(ctx, mongo.DbVersion, tenantId)
	} else {
		err = db.Migrate(ctx, mongo.DbVersion, nil)
	}
	if err != nil {
		return errors.Wrap(err, "failed to run migrations")
	}

	return nil

}

func commandSetPassword(c config.Reader, username, password, tenantId string) error {
	l := log.NewEmpty()

	l.Debugf("set password for '%s'", username)

	if password == "" {
		var err error
		if password, err = safeReadPassword(); err != nil {
			return err
		}
	}

	db, err := mongo.GetDataStoreMongo(dataStoreMongoConfigFromAppConfig(c))
	if err != nil {
		return errors.Wrap(err, "database connection failed")
	}

	ua := useradm.NewUserAdm(nil, db, mongo.NewTenantStoreMongo(db),
		useradm.Config{})

	u := model.User{
		Email:    username,
		Password: password,
	}

	if err := u.ValidateNew(); err != nil {
		return errors.Wrap(err, "user validation failed")
	}

	ctx := getTenantContext(tenantId)

	uu := model.UserUpdate{
		Email:    username,
		Password: password,
	}

	if err := ua.SetPassword(ctx, uu); err != nil {
		return errors.Wrap(err, "setting password failed")
	}

	return nil
}
