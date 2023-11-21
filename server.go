// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package main

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"

	api_http "github.com/mendersoftware/useradm/api/http"
	"github.com/mendersoftware/useradm/authz"
	"github.com/mendersoftware/useradm/client/tenant"
	"github.com/mendersoftware/useradm/common"
	. "github.com/mendersoftware/useradm/config"
	"github.com/mendersoftware/useradm/jwt"
	"github.com/mendersoftware/useradm/store/mongo"
	useradm "github.com/mendersoftware/useradm/user"
)

func SetupAPI(stacktype string, authz authz.Authorizer, jwth map[int]jwt.Handler,
	jwthFallback jwt.Handler) (*rest.Api, error) {
	api := rest.NewApi()
	if err := SetupMiddleware(api, stacktype, authz, jwth, jwthFallback); err != nil {
		return nil, errors.Wrap(err, "failed to setup middleware")
	}

	//this will override the framework's error resp to the desired one:
	// {"error": "msg"}
	// instead of:
	// {"Error": "msg"}
	rest.ErrorFieldName = "error"

	return api, nil
}

func RunServer(c config.Reader) error {

	l := log.New(log.Ctx{})

	authorizer := &SimpleAuthz{}

	// let's now go through all the existing keys and load them
	jwtHandlers, err := addPrivateKeys(
		filepath.Dir(c.GetString(SettingServerPrivKeyPath)),
		c.GetString(SettingServerPrivKeyFileNamePattern),
	)
	if err != nil {
		return err
	}
	defaultHandler, err := jwt.NewJWTHandler(
		SettingServerPrivKeyPathDefault,
		c.GetString(SettingServerPrivKeyFileNamePattern),
	)
	if err == nil && defaultHandler != nil {
		// the key with id 0 is by default the default one. this allows
		// to support tokens without "kid" in the header
		// it is possible, that you rotated the default key, in which case you have to
		// set USERADM_SERVER_PRIV_KEY_PATH=/etc/useradm/rsa/private.id.2048.pem
		// where private.id.2048.pem is the new key, with new id. the new one will by default
		// be used to issue new tokens, while any other token which has id that we have
		// will be authorized against its matching key (by id from "kid" in JWT header)
		// or which does not have "kid" will be authorized against the key with id 0.
		// in other words: the key with id 0 (if not present as private.id.0.pem)
		// is the default one, and all the JWT with no "kid" in headers are being
		// checked against it.
		jwtHandlers[common.KeyIdZero] = defaultHandler
	}
	var jwtFallbackHandler jwt.Handler
	fallback := c.GetString(SettingServerFallbackPrivKeyPath)
	if err == nil && fallback != "" {
		jwtFallbackHandler, err = jwt.NewJWTHandler(
			fallback,
			c.GetString(SettingServerPrivKeyFileNamePattern),
		)
	}
	if err != nil {
		return err
	}

	db, err := mongo.GetDataStoreMongo(dataStoreMongoConfigFromAppConfig(c))
	if err != nil {
		return errors.Wrap(err, "database connection failed")
	}

	ua := useradm.NewUserAdm(jwtHandlers, db,
		useradm.Config{
			Issuer:                         c.GetString(SettingJWTIssuer),
			ExpirationTimeSeconds:          int64(c.GetInt(SettingJWTExpirationTimeout)),
			LimitSessionsPerUser:           c.GetInt(SettingLimitSessionsPerUser),
			LimitTokensPerUser:             c.GetInt(SettingLimitTokensPerUser),
			TokenLastUsedUpdateFreqMinutes: c.GetInt(SettingTokenLastUsedUpdateFreqMinutes),
			PrivateKeyPath:                 c.GetString(SettingServerPrivKeyPath),
			PrivateKeyFileNamePattern:      c.GetString(SettingServerPrivKeyFileNamePattern),
		})

	if tadmAddr := c.GetString(SettingTenantAdmAddr); tadmAddr != "" {
		l.Infof("settting up tenant verification")

		tc := tenant.NewClient(tenant.Config{
			TenantAdmAddr: tadmAddr,
		})

		ua = ua.WithTenantVerification(tc)
	}

	useradmapi := api_http.NewUserAdmApiHandlers(ua, db, jwtHandlers,
		api_http.Config{
			TokenMaxExpSeconds: c.GetInt(SettingTokenMaxExpirationSeconds),
		})

	api, err := SetupAPI(
		c.GetString(SettingMiddleware),
		authorizer,
		jwtHandlers,
		jwtFallbackHandler,
	)
	if err != nil {
		return errors.Wrap(err, "API setup failed")
	}

	apph, err := useradmapi.GetApp()
	if err != nil {
		return errors.Wrap(err, "useradm API handlers setup failed")
	}
	api.SetApp(apph)

	addr := c.GetString(SettingListen)
	l.Printf("listening on %s", addr)

	return http.ListenAndServe(addr, api.MakeHandler())
}

func addPrivateKeys(
	privateKeysDirectory string,
	privateKeyPattern string,
) (handlers map[int]jwt.Handler, err error) {
	files, err := os.ReadDir(privateKeysDirectory)
	if err != nil {
		return
	}

	r, err := regexp.Compile(privateKeyPattern)
	if err != nil {
		return
	}

	handlers = make(map[int]jwt.Handler, len(files))
	for _, fileEntry := range files {
		if r.MatchString(fileEntry.Name()) {
			keyPath := path.Join(privateKeysDirectory, fileEntry.Name())
			handler, err := jwt.NewJWTHandler(keyPath, privateKeyPattern)
			if err != nil {
				continue
			}
			keyId := common.KeyIdFromPath(keyPath, privateKeyPattern)
			handlers[keyId] = handler
		}
	}
	return handlers, nil
}
