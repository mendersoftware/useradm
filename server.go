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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

func SetupAPI(stacktype string) (*rest.Api, error) {
	api := rest.NewApi()
	if err := SetupMiddleware(api, stacktype); err != nil {
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

	privKey, err := getRSAPrivKey(c.GetString(SettingPrivKeyPath))
	if err != nil {
		return errors.Wrap(err, "failed to read rsa private key")
	}

	useradmapi := NewUserAdmApiHandlers(
		func(l *log.Logger) (UserAdmApp, error) {
			db, err := GetDataStoreMongo(c.GetString(SettingDb), l)
			if err != nil {
				return nil, errors.Wrap(err, "database connection failed")
			}

			jwtHandler := NewJWTHandlerRS256(privKey, l)

			ua := NewUserAdm(jwtHandler, db, UserAdmConfig{
				Issuer:         c.GetString(SettingJWTIssuer),
				ExpirationTime: int64(c.GetInt(SettingJWTExpirationTimeout)),
			})
			return ua, nil
		})

	api, err := SetupAPI(c.GetString(SettingMiddleware))
	if err != nil {
		return errors.Wrap(err, "API setup failed")
	}

	apph, err := useradmapi.GetApp()
	if err != nil {
		return errors.Wrap(err, "inventory API handlers setup failed")
	}
	api.SetApp(apph)

	addr := c.GetString(SettingListen)
	l.Printf("listening on %s", addr)

	return http.ListenAndServe(addr, api.MakeHandler())
}

func getRSAPrivKey(privKeyPath string) (*rsa.PrivateKey, error) {
	// read key from file
	pemData, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "jwt: can't open key")
	}

	// decode pem key
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.Wrap(err, "jwt: can't decode key")
	}

	// check if it is an RSA PRIVATE KEY
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return nil, errors.New("jwt: can't open key - not an rsa private key")
	}

	// return parsed key
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "jwt: can't parse key")
	}

	return privkey, nil
}
