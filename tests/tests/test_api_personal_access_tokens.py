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
    init_users,
    init_users_f,
    init_users_mt,
    init_users_mt_f,
    cli,
    api_client_int,
    api_client_mgmt,
    mongo,
    make_auth,
)
import bravado
import pytest
import tenantadm


class TestManagementApiPostTokenBase:
    def _do_test_ok(
        self,
        api_client_int,
        api_client_mgmt,
        init_users,
        token_request,
        tenant_id=None,
    ):
        user = init_users[0]
        _, r = api_client_mgmt.login(user.email, "correcthorsebatterystaple")
        assert r.status_code == 200
        user_token = r.text

        auth = {"Authorization": "Bearer " + user_token}

        _, r = api_client_mgmt.create_token(token_request, auth)
        assert r.status_code == 200
        personal_access_token = r.text

        # check if the token is valid
        _, r = api_client_int.verify(personal_access_token)
        assert r.status_code == 200

        # get tokens
        tokens, r = api_client_mgmt.list_tokens(auth)
        assert r.status_code == 200
        assert len(tokens) == 1

        # revoke token
        r = api_client_mgmt.delete_token(tokens[0].id, auth)
        assert r.status_code == 204

        # verify token has been removed
        tokens, r = api_client_mgmt.list_tokens(auth)
        assert r.status_code == 200
        assert len(tokens) == 0
        with pytest.raises(bravado.exception.HTTPError) as e:
            _, r = api_client_int.verify(personal_access_token)
            assert e.response.status_code == 401


class TestManagementApiPostToken(TestManagementApiPostTokenBase):
    def test_ok(self, api_client_int, api_client_mgmt, init_users):
        token_request = {"name": "my_personal_access_token", "expires_in": 3600}
        self._do_test_ok(api_client_int, api_client_mgmt, init_users, token_request)


class TestManagementApiPostTokenEnterprise(TestManagementApiPostTokenBase):
    @pytest.mark.parametrize("tenant_id", ["tenant1id", "tenant2id"])
    def test_ok(self, tenant_id, api_client_int, api_client_mgmt, init_users_mt):
        token_request = {"name": "my_personal_access_token", "expires_in": 3600}
        users_db = {
            tenant: [user.email for user in users]
            for tenant, users in init_users_mt.items()
        }

        with tenantadm.run_fake_user_tenants(users_db):
            self._do_test_ok(
                api_client_int, api_client_mgmt, init_users_mt[tenant_id], token_request
            )
