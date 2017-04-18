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
	"context"
	"fmt"
	"os"

	"github.com/mendersoftware/go-lib-micro/config"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/urfave/cli"

	"github.com/mendersoftware/useradm/store/mongo"
)

func main() {
	var debug bool
	var configPath string

	app := cli.NewApp()
	app.Version = CreateVersionString()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config",
			Usage:       "Configuration `FILE`. Supports JSON, TOML, YAML and HCL formatted configs.",
			Destination: &configPath,
		},
		cli.BoolFlag{
			Name:  "dev",
			Usage: "Use development setup",
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "Enable debug logging",
			Destination: &debug,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "server",
			Usage:  "Run as server (default)",
			Action: runDeamon,
		},
	}
	app.Action = runDeamon
	app.Before = func(args *cli.Context) error {
		log.Setup(debug)

		err := config.FromConfigFile(configPath, configDefaults)
		if err != nil {
			return cli.NewExitError(
				fmt.Sprintf("error loading configuration: %s", err),
				1)
		}

		// Enable setting conig values by environment variables
		config.Config.SetEnvPrefix("USERADM")
		config.Config.AutomaticEnv()

		return nil
	}
	app.Run(os.Args)
}

func runDeamon(args *cli.Context) error {
	devSetup := args.GlobalBool("dev")

	l := log.New(log.Ctx{})

	if devSetup {
		l.Infof("setting up development configuration")
		config.Config.Set(SettingMiddleware, EnvDev)
	}

	/*l.Printf("Inventory Service, version %s starting up",
	CreateVersionString())*/

	ctx := context.Background()

	db, err := mongo.NewDataStoreMongo(config.Config.GetString(SettingDb))
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to connect to db: %v", err),
			2)
	}

	err = db.Migrate(ctx, mongo.DbVersion, nil)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to run migrations: %v", err),
			3)
	}

	err = RunServer(config.Config)
	if err != nil {
		return cli.NewExitError(err.Error(), 4)
	}
	return nil
}
