#!/usr/bin/python
# Copyright 2022 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
from common import (
    cli,
    api_client_mgmt,
    mongo,
    clean_db,
    make_auth,
    migrate,
    explode_jwt,
)
import bravado
import pytest
import semver
import tenantadm


class Migration:
    DB_NAME = "useradm"
    MIGRATION_COLLECTION = "migration_info"
    DB_VERSION = "1.3.2"

    @staticmethod
    def verify_db_and_collections(client, dbname):
        dbs = client.list_database_names()
        assert dbname in dbs

        colls = client[dbname].list_collection_names()
        assert Migration.MIGRATION_COLLECTION in colls

    @staticmethod
    def verify_migration(db, expected_version):
        expected_version = semver.VersionInfo.parse(expected_version)

        migrations = list(db[Migration.MIGRATION_COLLECTION].find({}))
        semvers = list()
        for migration in migrations:
            version: str = ".".join(str(ver_part) for ver_part in list(migration["version"].values()))
            semvers.append(semver.VersionInfo.parse(version))

        assert len(semvers) != 0, "DB: No migrations found"
        latest_migration_version = sorted(semvers)[-1]
        assert expected_version == latest_migration_version, f"Expected migration version {expected_version} is different than latest found: {latest_migration_version}"


class TestCli:
    def test_create_user(self, api_client_mgmt, cli, clean_db):
        cli.create_user("foo@bar.com", "1234youseeme")
        users = api_client_mgmt.get_users()
        assert [user for user in users if user.email == "foo@bar.com"]

    def test_create_user_login(self, api_client_mgmt, cli, clean_db):
        email = "foo@bar.com"
        password = "1234youseeme"
        cli.create_user(email, password)
        _, r = api_client_mgmt.login(email, password)
        assert r.status_code == 200

        token = r.text
        assert token

    def test_create_user_with_id(self, api_client_mgmt, cli, clean_db):
        cli.create_user("foo@bar.com", "1234youseeme", user_id="123456")
        users = api_client_mgmt.get_users()
        assert [
            user
            for user in users
            if user.email == "foo@bar.com" and user.id == "123456"
        ]

    def test_create_user_with_id(self, api_client_mgmt, cli, clean_db):
        cli.create_user("foo@bar.com", "1234youseeme", user_id="123456")
        users = api_client_mgmt.get_users()
        assert [
            user
            for user in users
            if user.email == "foo@bar.com" and user.id == "123456"
        ]

    def test_set_password(self, api_client_mgmt, cli, clean_db):
        password = "1234youseeme"
        new_password = "5678youseeme"
        email = "foo@bar.com"
        cli.create_user(email, password)
        _, r = api_client_mgmt.login(email, password)
        assert r.status_code == 200
        cli.set_password(email, new_password)
        status_code = 200
        try:
            _, r = api_client_mgmt.login(email, password)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 401
            status_code = 401
        assert status_code == 401
        _, r = api_client_mgmt.login(email, new_password)
        assert r.status_code == 200

    def test_migrate(self, cli, clean_db, mongo):
        cli.migrate()

        Migration.verify_db_and_collections(mongo, Migration.DB_NAME)
        Migration.verify_migration(mongo[Migration.DB_NAME], Migration.DB_VERSION)


class TestCliEnterprise:
    def test_create_user(self, api_client_mgmt, cli):
        user = {"email": "foo-tenant1id@bar.com", "password": "1234youseeme"}

        with tenantadm.run_fake_create_user(user):
            cli.create_user(user["email"], user["password"], tenant_id="tenant1id")

        users = api_client_mgmt.get_users(make_auth("foo", tenant="tenant1id"))
        assert [user for user in users if user.email == "foo-tenant1id@bar.com"]

        other_tenant_users = api_client_mgmt.get_users(
            make_auth("foo", tenant="tenant2id")
        )
        assert not other_tenant_users

    def test_create_user_login(self, api_client_mgmt, cli, clean_db):
        user = {"email": "foo@bar.com", "password": "1234youseeme"}

        users_db = {"tenant1id": [user["email"]]}

        with tenantadm.run_fake_create_user(user):
            cli.create_user(user["email"], user["password"], tenant_id="tenant1id")

        with tenantadm.run_fake_user_tenants(users_db):
            _, r = api_client_mgmt.login(user["email"], user["password"])
            assert r.status_code == 200

            token = r.text
            assert token
            _, claims, _ = explode_jwt(token)
            assert claims["mender.tenant"] == "tenant1id"

    def test_set_password(self, api_client_mgmt, cli, clean_db):
        user = {
            "password": "1234youseeme",
            "new_password": "5678youseeme",
            "email": "foo@bar.com",
            "tenant": "tenant1id",
        }

        users_db = {user["tenant"]: [user["email"]]}

        with tenantadm.run_fake_create_user(user):
            cli.create_user(user["email"], user["password"], tenant_id=user["tenant"])

        with tenantadm.run_fake_user_tenants(users_db):
            _, r = api_client_mgmt.login(user["email"], user["password"])
            assert r.status_code == 200

            cli.set_password(user["email"], user["new_password"], user["tenant"])
            status_code = 200
            try:
                _, r = api_client_mgmt.login(user["email"], user["password"])
            except bravado.exception.HTTPError as e:
                assert e.response.status_code == 401
                status_code = 401
            assert status_code == 401
            _, r = api_client_mgmt.login(user["email"], user["new_password"])
            assert r.status_code == 200

            token = r.text
            assert token
            _, claims, _ = explode_jwt(token)
            assert claims["mender.tenant"] == user["tenant"]

    def test_migrate(self, cli, clean_db, mongo):
        cli.migrate(tenant_id="0000000000000000000000")

        tenant_db = Migration.DB_NAME + "-0000000000000000000000"
        Migration.verify_db_and_collections(mongo, tenant_db)
        Migration.verify_migration(mongo[tenant_db], Migration.DB_VERSION)
