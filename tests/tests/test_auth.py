#!/usr/bin/python
# Copyright 2017 Mender Software AS
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
import json
from common import init_users, init_users_f, init_users_mt, \
    init_users_mt_f, cli, api_client_mgmt, api_client_int, mongo, \
    make_auth, user_tokens, explode_jwt
from mockserver import run_fake
import bravado
import pytest
import tenantadm
from base64 import urlsafe_b64encode


class TestAuthLogin:
    @pytest.mark.parametrize("email,password", [
        ("foo@bar.com", "asdf1234zxcv"),
        ("user-1@foo.com", "asdf1234zxcv"),
        ("user-1@foo.com", ""),
        ])
    def test_bad_user(self, api_client_mgmt, init_users, email, password):
        try:
            _, r = api_client_mgmt.login(email, password)
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 401

    def test_ok(self, api_client_mgmt, init_users):
        email = "user-1@foo.com"
        password = "correcthorsebatterystaple"

        _, r = api_client_mgmt.login(email, password)
        assert r.status_code == 200

        token = r.text
        assert len(token)
        _, claims, _ = explode_jwt(token)
        assert 'mender.user' in claims and claims['mender.user'] == True


class TestAuthLoginMultitenant:
    def test_ok(self, api_client_mgmt, init_users_mt):
        password = "correcthorsebatterystaple"

        users_db = { tenant: [user.email for user in users] \
                     for tenant, users in init_users_mt.items() }

        with tenantadm.run_fake_user_tenants(users_db):
            for tenant, users in users_db.items():
                for email in users:
                    _, r = api_client_mgmt.login(email, password)
                    assert r.status_code == 200
                    assert r.headers['Content-Type'] == "application/jwt"
                    _, claims, _ = explode_jwt(r.text)
                    assert claims['mender.tenant'] == tenant

    @pytest.mark.parametrize("email,password", [
        ("foo@bar.com", "asdf1234zxcv"),
        ("user-1@foo.com", "asdf1234zxcv"),
        ("user-1@foo.com", ""),
        ])
    def test_bad_user(self, api_client_mgmt, email, password):
        with tenantadm.run_fake_user_tenants({}):
            try:
                _, r = api_client_mgmt.login(email, password)
            except bravado.exception.HTTPError as herr:
                assert herr.response.status_code == 401


class TestAuthVerify:
    @pytest.mark.parametrize("token", [
        "garbage",
        "",
        make_auth("user-1@foo.com")["Authorization"],
        ])
    def test_fail(self, api_client_int, init_users, token):
        try:
            _, r = api_client_int.verify(token)
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 401

    def test_ok(self, api_client_int, init_users, user_tokens):
        for user, token in zip(init_users, user_tokens):
            _, r = api_client_int.verify(token)

            assert r.status_code == 200

    def test_tamper_claims(self, api_client_int, init_users, user_tokens):
        for user, token in zip(init_users, user_tokens):
            hdr, claims, sign = explode_jwt(token)
            claims['mender.tenant'] = 'foobar'

            tampered = '.'.join([urlsafe_b64encode(json.dumps(hdr).encode()).decode(),
                                 urlsafe_b64encode(json.dumps(claims).encode()).decode(),
                                 urlsafe_b64encode(sign).decode()])
            try:
                _, r = api_client_int.verify(tampered)
            except bravado.exception.HTTPError as herr:
                assert herr.response.status_code == 401


    def test_bad_x_original(self, api_client_int, init_users, user_tokens):
        user, token  = init_users[0], user_tokens[0]
        try:
            _, r = api_client_int.verify(token, uri='/foobar')
        except bravado.exception.HTTPError as herr:
            assert herr.response.status_code == 500
