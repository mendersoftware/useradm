#!/usr/bin/python
# Copyright 2016 Mender Software AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
from common import init_users,cli,api_client_mgmt, mongo, make_auth
import bravado

class TestManagementApiPostUsersBase:
    def _do_test_ok(self, api_client_mgmt, init_users, tenant_id=None):
        auth=None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        new_user = {"email":"foo@bar.com", "password": "asdf1234zxcv"}

        _, r = api_client_mgmt.create_user(new_user, auth)
        assert r.status_code == 201

        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users) + 1

        found_user = [u for u in users if u.email == new_user["email"]]
        assert len(found_user) == 1
        found_user = found_user[0]

    def _do_test_fail_duplicate_email(self, api_client_mgmt, init_users, tenant_id=None):
        auth=None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        new_user = {"email":init_users[0].email, "password": "asdf1234zxcv"}
        try:
            api_client_mgmt.create_user(new_user, auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 422


class TestManagementApiPostUsers(TestManagementApiPostUsersBase):
    def test_ok(self, api_client_mgmt, init_users):
        self._do_test_ok(api_client_mgmt, init_users)

    def test_fail_malformed_body(self, api_client_mgmt):
        new_user = {"foo":"bar"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_no_password(self, api_client_mgmt):
        new_user = {"email":"foobar"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_no_email(self, api_client_mgmt):
        new_user = {"password": "asdf1234zxcv"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_not_an_email(self, api_client_mgmt):
        new_user = {"email":"foobar", "password": "asdf1234zxcv"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_pwd_too_short(self, api_client_mgmt):
        new_user = {"email":"foo@bar.com", "password": "asdf"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 422

    def test_fail_duplicate_email(self, api_client_mgmt, init_users):
        self._do_test_fail_duplicate_email(api_client_mgmt, init_users)
