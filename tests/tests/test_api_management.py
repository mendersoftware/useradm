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
from common import (
    init_users,
    init_users_f,
    init_users_mt,
    init_users_mt_f,
    cli,
    api_client_mgmt,
    mongo,
    make_auth,
)
import bravado
import pytest
import tenantadm


class TestManagementApiPostUsersBase:
    def _do_test_ok(self, api_client_mgmt, init_users, new_user, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        _, r = api_client_mgmt.create_user(new_user, auth)
        assert r.status_code == 201

        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users) + 1

        found_user = [u for u in users if u.email == new_user["email"]]
        assert len(found_user) == 1
        found_user = found_user[0]

    def _do_test_fail_duplicate_email(
        self, api_client_mgmt, init_users, new_user, tenant_id=None
    ):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        try:
            api_client_mgmt.create_user(new_user, auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 422


class TestManagementApiPostUsers(TestManagementApiPostUsersBase):
    def test_ok(self, api_client_mgmt, init_users):
        new_user = {"email": "foo@bar.com", "password": "asdf1234zxcv"}
        self._do_test_ok(api_client_mgmt, init_users, new_user)

    def test_fail_malformed_body(self, api_client_mgmt):
        new_user = {"foo": "bar"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_no_password(self, api_client_mgmt):
        new_user = {"email": "foobar"}
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
        new_user = {"email": "foobar", "password": "asdf1234zxcv"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def test_fail_pwd_too_short(self, api_client_mgmt):
        new_user = {"email": "foo@bar.com", "password": "asdf"}
        try:
            api_client_mgmt.create_user(new_user)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 422

    def test_fail_duplicate_email(self, api_client_mgmt, init_users):
        new_user = {"email": "foo@bar.com", "password": "asdf"}
        self._do_test_fail_duplicate_email(api_client_mgmt, init_users, new_user)


class TestManagementApiPostUsersEnterprise(TestManagementApiPostUsersBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, tenant_id, api_client_mgmt, init_users_mt):
        new_user = {"email": "foo@bar.com", "password": "asdf1234zxcv"}
        with tenantadm.run_fake_create_user(new_user):
            self._do_test_ok(
                api_client_mgmt, init_users_mt[tenant_id], new_user, tenant_id
            )

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_fail_duplicate_email(self, tenant_id, api_client_mgmt, init_users_mt):
        new_user = {"email": "foo@bar.com", "password": "asdf1234zxcv"}
        with tenantadm.run_fake_create_user(new_user, 422):
            self._do_test_fail_duplicate_email(
                api_client_mgmt, init_users_mt[tenant_id], new_user, tenant_id
            )


class TestManagementApiGetUserBase:
    def _do_test_ok(self, api_client_mgmt, init_users, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        for u in init_users:
            found = api_client_mgmt.get_user(u.id, auth)
            assert found.id == u.id
            assert found.email == u.email
            assert found.created_ts == u.created_ts
            assert found.updated_ts == u.updated_ts

    def _do_test_fail_not_found(self, api_client_mgmt, init_users, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        try:
            not_found = api_client_mgmt.get_user("madeupid", auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404


class TestManagementApiGetUser(TestManagementApiGetUserBase):
    def test_ok(self, api_client_mgmt, init_users):
        self._do_test_ok(api_client_mgmt, init_users)

    def test_fail_not_found(self, api_client_mgmt, init_users):
        self._do_test_fail_not_found(api_client_mgmt, init_users)


class TestManagementApiGetUserEnterprise(TestManagementApiGetUserBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, tenant_id, api_client_mgmt, init_users_mt):
        self._do_test_ok(api_client_mgmt, init_users_mt[tenant_id], tenant_id)

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_fail_not_found(self, tenant_id, api_client_mgmt, init_users_mt):
        self._do_test_fail_not_found(
            api_client_mgmt, init_users_mt[tenant_id], tenant_id
        )


class TestManagementApiGetUsersBase:
    def _do_test_ok(self, api_client_mgmt, init_users, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users)

    def _do_test_no_users(self, api_client_mgmt, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        users = api_client_mgmt.get_users(auth)
        assert len(users) == 0


class TestManagementApiGetUsersOk(TestManagementApiGetUsersBase):
    def test_ok(self, api_client_mgmt, init_users):
        self._do_test_ok(api_client_mgmt, init_users)


class TestManagementApiGetUsersNoUsers(TestManagementApiGetUsersBase):
    def test_no_users(self, api_client_mgmt):
        self._do_test_no_users(api_client_mgmt)


class TestManagementApiGetUsersEnterprise(TestManagementApiGetUsersBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, tenant_id, api_client_mgmt, init_users_mt):
        self._do_test_ok(api_client_mgmt, init_users_mt[tenant_id], tenant_id)

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_no_users(self, tenant_id, api_client_mgmt, init_users_mt):
        self._do_test_no_users(api_client_mgmt, "non_existing_tenant_id")


class TestManagementApiDeleteUserBase:
    def _do_test_ok(self, api_client_mgmt, init_users, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        rsp = api_client_mgmt.delete_user(init_users[0]["id"], auth)
        assert rsp.status_code == 204

        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users) - 1

        found = [u for u in users if u.id == init_users[0]["id"]]
        assert len(found) == 0

    def _do_test_not_found(self, api_client_mgmt, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        rsp = api_client_mgmt.delete_user("nonexistent_id", auth)
        assert rsp.status_code == 204


class TestManagementApiDeleteUser(TestManagementApiDeleteUserBase):
    def test_ok(self, api_client_mgmt, init_users):
        self._do_test_ok(api_client_mgmt, init_users)

    def test_not_found(self, api_client_mgmt, init_users):
        self._do_test_not_found(api_client_mgmt)


class TestManagementApiDeleteUserEnterprise(TestManagementApiDeleteUserBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, tenant_id, api_client_mgmt, init_users_mt):
        with tenantadm.run_fake_delete_user(
            tenant_id, init_users_mt[tenant_id][0]["id"]
        ):
            self._do_test_ok(api_client_mgmt, init_users_mt[tenant_id], tenant_id)

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_not_found(self, tenant_id, api_client_mgmt):
        with tenantadm.run_fake_delete_user():
            self._do_test_not_found(api_client_mgmt, tenant_id)


class TestManagementApiPutUserBase:
    def _do_test_ok_email(
        self, api_client_mgmt, init_users, user, update, tenant_id=None
    ):
        _, r = api_client_mgmt.login(user.email, 'correcthorsebatterystaple')
        assert r.status_code == 200
        token = r.text
        auth = {"Authorization": "Bearer " + token}

        # test update
        _, r = api_client_mgmt.update_user(user.id, update, auth)
        assert r.status_code == 204

        # get/verify users
        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users)

        found = [u for u in users if u.email == update["email"]]
        assert len(found) == 1

    def _do_test_ok_email_or_pass(
        self, api_client_mgmt, init_users, user, update, tenant_id=None
    ):
        _, r = api_client_mgmt.login(user.email, 'correcthorsebatterystaple')
        assert r.status_code == 200
        token = r.text
        auth = {"Authorization": "Bearer " + token}

        # test update
        _, r = api_client_mgmt.update_user(user.id, update, auth)
        assert r.status_code == 204

        # get/verify users
        users = api_client_mgmt.get_users(auth)
        assert len(users) == len(init_users)

        # find the user via (new?) email
        email = user.email
        new_email = update.get("email", None)
        if new_email != None and new_email != user.email:
            email = new_email

        found = [u for u in users if u.email == email]
        assert len(found) == 1

        # try if login still works
        _, r = api_client_mgmt.login(email, update["password"])

        assert r.status_code == 200

    def _do_test_fail_not_found(
        self, api_client_mgmt, init_users, update, tenant_id=None
    ):
        _, r = api_client_mgmt.login(init_users[0].email, 'correcthorsebatterystaple')
        assert r.status_code == 200
        token = r.text
        auth = {"Authorization": "Bearer " + token}

        try:
            _, r = api_client_mgmt.update_user("madeupid", update, auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 404

    def _do_test_fail_bad_update(self, api_client_mgmt, init_users, tenant_id=None):
        try:
            _, r = api_client_mgmt.update_user(init_users[0].id, {"foo": "bar"})
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400

    def _do_test_fail_duplicate_email(
        self, api_client_mgmt, init_users, user, update, tenant_id=None
    ):
        _, r = api_client_mgmt.login(user.email, 'correcthorsebatterystaple')
        assert r.status_code == 200
        token = r.text
        auth = {"Authorization": "Bearer " + token}

        try:
            _, r = api_client_mgmt.update_user(user.id, update, auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 422


class TestManagementApiPutUser(TestManagementApiPutUserBase):
    def test_ok_email(self, api_client_mgmt, init_users_f):
        update = {"email": "unique1@foo.com"}
        self._do_test_ok_email(api_client_mgmt, init_users_f, init_users_f[0], update)

    def test_ok_pass(self, api_client_mgmt, init_users_f):
        update = {"password": "secretpassword123"}
        self._do_test_ok_email_or_pass(
            api_client_mgmt, init_users_f, init_users_f[0], update
        )

    def test_ok_email_and_pass(self, api_client_mgmt, init_users_f):
        update = {"email": "definitelyunique@foo.com", "password": "secretpassword123"}
        self._do_test_ok_email_or_pass(
            api_client_mgmt, init_users_f, init_users_f[0], update
        )

    def test_fail_not_found(self, api_client_mgmt, init_users_f):
        update = {"email": "foo@bar.com", "password": "secretpassword123"}
        self._do_test_fail_not_found(api_client_mgmt, init_users_f, update)

    def test_fail_bad_update(self, api_client_mgmt, init_users_f):
        self._do_test_fail_bad_update(api_client_mgmt, init_users_f)

    def test_fail_duplicate_email(self, api_client_mgmt, init_users_f):
        update = {"email": init_users_f[1].email, "password": "secretpassword123"}
        self._do_test_fail_duplicate_email(
            api_client_mgmt, init_users_f, init_users_f[0], update
        )


class TestManagementApiPutUserEnterprise(TestManagementApiPutUserBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok_email(self, api_client_mgmt, init_users_mt_f, tenant_id):
        user = init_users_mt_f[tenant_id][0]
        update = {"email": "unique1@foo.com"}
        with tenantadm.run_fake_update_user(tenant_id, user.id, update):
            self._do_test_ok_email(
                api_client_mgmt, init_users_mt_f[tenant_id], user, update, tenant_id
            )

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok_pass(self, api_client_mgmt, init_users_mt_f, tenant_id):
        user = init_users_mt_f[tenant_id][1]
        with tenantadm.run_fake_get_tenants(tenant_id):
            update = {"password": "secretpassword123"}
            self._do_test_ok_email_or_pass(
                api_client_mgmt, init_users_mt_f[tenant_id], user, update, tenant_id
            )

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok_email_and_pass(self, api_client_mgmt, init_users_mt_f, tenant_id):
        user = init_users_mt_f[tenant_id][2]
        update = {"email": "definitelyunique@foo.com", "password": "secretpassword123"}
        with tenantadm.run_fake_update_user(tenant_id, user.id, update):
            self._do_test_ok_email_or_pass(
                api_client_mgmt, init_users_mt_f[tenant_id], user, update, tenant_id
            )

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_fail_not_found(self, api_client_mgmt, init_users_mt_f, tenant_id):
        user = init_users_mt_f[tenant_id][3]
        update = {"email": "foo@bar.com", "password": "secretpassword123"}
        with tenantadm.run_fake_update_user(tenant_id, user.id, update, 404):
            self._do_test_fail_not_found(
                api_client_mgmt, init_users_mt_f[tenant_id], update, tenant_id
            )

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_fail_bad_update(self, api_client_mgmt, init_users_mt_f, tenant_id):
        self._do_test_fail_bad_update(api_client_mgmt, init_users_mt_f[tenant_id])

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_fail_duplicate_email(self, api_client_mgmt, init_users_mt_f, tenant_id):
        user = init_users_mt_f[tenant_id][0]
        update = {
            "email": init_users_mt_f[tenant_id][1].email,
            "password": "secretpassword123",
        }
        with tenantadm.run_fake_update_user(tenant_id, user.id, update, 422):
            self._do_test_fail_duplicate_email(
                api_client_mgmt, init_users_mt_f[tenant_id], user, update, tenant_id
            )


class TestManagementApiSettingsBase:
    def _do_test_ok(self, api_client_mgmt, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        # nonempty
        self._set_and_verify(
            {"foo": "foo-val", "bar": "bar-val"}, api_client_mgmt, auth
        )

        # empty
        self._set_and_verify({}, api_client_mgmt, auth)

    def _do_test_no_settings(self, api_client_mgmt, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        found = api_client_mgmt.get_settings(auth)
        assert found.json() == {}

    def _set_and_verify(self, settings, api_client_mgmt, auth):
        r = api_client_mgmt.post_settings(settings, auth)
        assert r.status_code == 201

        found = api_client_mgmt.get_settings(auth)
        assert found.json() == settings

    def _do_test_fail_bad_request(self, api_client_mgmt, tenant_id=None):
        auth = None
        if tenant_id is not None:
            auth = make_auth("foo", tenant_id)

        try:
            r = api_client_mgmt.post_settings("asdf", auth)
        except bravado.exception.HTTPError as e:
            assert e.response.status_code == 400


class TestManagementApiSettings(TestManagementApiSettingsBase):
    def test_ok(self, api_client_mgmt):
        self._do_test_ok(api_client_mgmt)

    def test_no_settings(self, api_client_mgmt):
        self._do_test_no_settings(api_client_mgmt)

    def test_bad_request(self, api_client_mgmt):
        self._do_test_fail_bad_request(api_client_mgmt)


class TestManagementApiSettingsEnterprise(TestManagementApiSettingsBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, api_client_mgmt, init_users_mt_f, tenant_id):
        self._do_test_ok(api_client_mgmt, tenant_id)

    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_bad_request(self, api_client_mgmt, tenant_id):
        self._do_test_fail_bad_request(api_client_mgmt, tenant_id)
