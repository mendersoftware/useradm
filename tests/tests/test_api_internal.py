#!/usr/bin/python
# Copyright 2021 Northern.tech AS
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
from common import api_client_int, mongo, clean_db, make_auth, api_client_mgmt
import bravado
import pytest
import tenantadm


class TestInternalApiTenantCreate:
    def test_create_ok(self, api_client_int, clean_db):

        _, r = api_client_int.create_tenant("foobar")
        assert r.status_code == 201

        assert "useradm-foobar" in clean_db.database_names()
        assert "migration_info" in clean_db["useradm-foobar"].collection_names()

    def test_create_twice(self, api_client_int, clean_db):

        _, r = api_client_int.create_tenant("foobar")
        assert r.status_code == 201

        # creating once more should not fail
        _, r = api_client_int.create_tenant("foobar")
        assert r.status_code == 201

    def test_create_empty(self, api_client_int):
        try:
            _, r = api_client_int.create_tenant("")
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400


class TestInternalApiUserForTenantCreateEnterprise:
    def test_ok(
        self, api_client_int, api_client_mgmt, clean_db,
    ):
        user = {"email": "stefan@example.com", "password": "secret12345"}

        with tenantadm.run_fake_create_user(user):
            api_client_int.create_user_for_tenant("foobar", user)

        auth = make_auth("foo", "foobar")
        users = api_client_mgmt.get_users(auth)
        assert len(users) == 1

    def test_ok_pwd_hash(self, api_client_int, api_client_mgmt, clean_db):
        user = {
            "email": "stefan@example.com",
            "password_hash": "secret12345",
            "propagate": False,
        }

        with tenantadm.run_fake_create_user(user):
            api_client_int.create_user_for_tenant("foobar", user)

        auth = make_auth("foo", "foobar")
        users = api_client_mgmt.get_users(auth)
        assert len(users) == 1

    def test_no_propagate(
        self, api_client_int, api_client_mgmt, clean_db,
    ):
        user = {
            "email": "stefan@example.com",
            "password": "secret12345",
            "propagate": False,
        }

        with tenantadm.run_fake_create_user(user, 500):
            api_client_int.create_user_for_tenant("foobar", user)

        auth = make_auth("foo", "foobar")
        users = api_client_mgmt.get_users(auth)
        assert len(users) == 1

    def test_fail_malformed_body(self, api_client_int):
        new_user = {"foo": "bar"}
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")

    def test_fail_no_password(self, api_client_int):
        new_user = {"email": "foo@bar.bz"}
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")

    def test_fail_pwd_and_hash(self, api_client_int, api_client_mgmt, clean_db):
        new_user = {
            "email": "foobar@tenant.com",
            "password": "secret1234",
            "password_hash": "secret1234",
        }
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")

    def test_fail_no_email(self, api_client_int):
        new_user = {"password": "asdf1234zxcv"}
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")

    def test_fail_not_an_email(self, api_client_int):
        new_user = {"email": "foobar", "password": "asdf1234zxcv"}
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")

    def test_fail_pwd_too_short(self, api_client_int):
        new_user = {"email": "foo@bar.com", "password": "asdf"}
        try:
            api_client_int.create_user_for_tenant("foobar", new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400
        else:
            pytest.fail("Exception expected")
