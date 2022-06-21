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
import json
from common import (
    init_users,
    init_users_f,
    init_users_mt,
    init_users_mt_f,
    cli,
    api_client_mgmt,
    api_client_int,
    mongo,
    migrate,
    make_auth,
    user_tokens,
    explode_jwt,
)
from mockserver import run_fake
import bravado
import pytest
import tenantadm
import requests
import uuid
from base64 import urlsafe_b64encode


def verify_token(api_client_int, token, status_code):
    try:
        _, r = api_client_int.verify(token)
    except bravado.exception.HTTPError as herr:
        assert herr.response.status_code == status_code
    else:
        assert r.status_code == status_code


def verify_tokens(api_client_int, tokens, removed_tenant=None, removed_user=None):
    for t in tokens:
        if removed_tenant is None:
            verify_token(api_client_int, t, 200)
        else:
            _, claims, _ = explode_jwt(t)
            tenant = claims["mender.tenant"]
            user = claims["sub"]
            if (
                removed_user is None or user == removed_user
            ) and tenant == removed_tenant:
                verify_token(api_client_int, t, 401)
            else:
                verify_token(api_client_int, t, 200)


@pytest.fixture(scope="function")
def user_tokens_mt_f(init_users_mt_f, api_client_mgmt):
    tokens = []
    password = "correcthorsebatterystaple"

    users_db = {
        tenant: [user.email for user in users]
        for tenant, users in init_users_mt_f.items()
    }

    with tenantadm.run_fake_user_tenants(users_db):
        for tenant, users in users_db.items():
            for email in users:
                _, r = api_client_mgmt.login(email, password)
                assert r.status_code == 200
                assert r.headers["Content-Type"] == "application/jwt"
                tokens.append(r.text)

    yield tokens


class TestDeleteTokensEnterprise:
    def test_delete_by_user_ok(self, api_client_int, user_tokens_mt_f):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        _, claims, _ = explode_jwt(user_tokens_mt_f[0])
        tenant = claims["mender.tenant"]
        user = claims["sub"]

        payload = {"user_id": user, "tenant_id": tenant}
        rsp = requests.delete(api_client_int.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_tokens(api_client_int, tokens, tenant, user)

    def test_delete_by_tenant_ok(self, api_client_int, user_tokens_mt_f):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        _, claims, _ = explode_jwt(user_tokens_mt_f[0])
        tenant = claims["mender.tenant"]

        payload = {"tenant_id": tenant}
        rsp = requests.delete(api_client_int.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_tokens(api_client_int, tokens, tenant)

    def test_delete_by_non_existent_user_ok(self, api_client_int, user_tokens_mt_f):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        _, claims, _ = explode_jwt(user_tokens_mt_f[0])
        tenant = claims["mender.tenant"]

        payload = {"user_id": str(uuid.uuid4()), "tenant_id": tenant}
        rsp = requests.delete(api_client_int.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_tokens(api_client_int, tokens)

    def test_delete_by_non_existent_tenant_ok(self, api_client_int, user_tokens_mt_f):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        payload = {"tenant_id": "foo"}
        rsp = requests.delete(api_client_int.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 204

        verify_tokens(api_client_int, tokens)

    def test_delete_no_tenant_id_bad_request(self, api_client_int, user_tokens_mt_f):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        payload = {"user_id": "foo"}
        rsp = requests.delete(api_client_int.make_api_url("/tokens"), params=payload)
        assert rsp.status_code == 400

    def test_delete_no_user_id_no_tenant_id_bad_request(
        self, api_client_int, user_tokens_mt_f
    ):
        tokens = user_tokens_mt_f
        for t in tokens:
            verify_token(api_client_int, t, 200)

        rsp = requests.delete(api_client_int.make_api_url("/tokens"))
        assert rsp.status_code == 400
