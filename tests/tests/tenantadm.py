#!/usr/bin/python3
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
import json
import os
import logging

from contextlib import contextmanager

import mockserver

def get_fake_tenantadm_addr():
    return os.environ.get('FAKE_TENANTADM_ADDR', '0.0.0.0:9997')

def fake_create_user(user, status):
    def create_user(request):
        req_user = json.loads(request.body.decode())
        assert req_user["name"] == user["email"]
        return (status, {}, '')

    return create_user

@contextmanager
def run_fake_create_user(user, status=201):
    handlers = [
            ('POST', '/api/internal/v1/tenantadm/users', fake_create_user(user, status))
        ]

    with mockserver.run_fake(get_fake_tenantadm_addr(),
                             handlers=handlers) as server:
        yield server

def fake_delete_user(expected_tenant_id, expected_user_id):
    def delete_user(_request, tenant_id, user_id):
        if expected_tenant_id is not None:
            assert tenant_id == expected_tenant_id
        if expected_user_id is not None:
            assert user_id == expected_user_id
        return (204, {}, '')

    return delete_user

@contextmanager
def run_fake_delete_user(expected_tenant_id=None, expected_user_id=None):
    handlers = [
            ('DELETE', '/api/internal/v1/tenantadm/tenants/(.*)/users/(.*)',
             fake_delete_user(expected_tenant_id, expected_user_id))
        ]

    with mockserver.run_fake(get_fake_tenantadm_addr(),
                             handlers=handlers) as server:
        yield server
