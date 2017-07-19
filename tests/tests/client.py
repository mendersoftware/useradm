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
import os.path
import logging
import pytest
import common
from bravado.swagger_model import load_file
from bravado.client import SwaggerClient, RequestsClient
import subprocess
import requests


class ApiClient:
    config = {
        'also_return_response': True,
        'validate_responses': True,
        'validate_requests': False,
        'validate_swagger_spec': False,
        'use_models': True,
    }

    log = logging.getLogger('client.ApiClient')
    # override spec_option for internal vs management clients
    spec_option = 'internal-spec'
    api_url = "http://%s/api/0.1.0/" % \
              pytest.config.getoption("host")

    def make_api_url(self, path):
        return os.path.join(self.api_url,
                            path if not path.startswith("/") else path[1:])

    def setup_swagger(self):
        self.http_client = RequestsClient()
        self.http_client.session.verify = False

        spec = pytest.config.getoption(self.spec_option)
        self.client = SwaggerClient.from_spec(load_file(spec),
                                              config=self.config,
                                              http_client=self.http_client)
        self.client.swagger_spec.api_url = self.api_url

    def __init__(self):
        self.setup_swagger()


class InternalApiClient(ApiClient):
    log = logging.getLogger('client.InternalClient')
    spec_option = 'internal_spec'

    def __init__(self):
        super().__init__()


class ManagementApiClient(ApiClient):
    log = logging.getLogger('client.ManagementClient')
    spec_option = 'management_spec'

    # default user auth - single user, single tenant
    auth = {"Authorization": "Bearer foobarbaz"}

    def __init__(self):
        super().__init__()

    def get_users(self, auth=None):
        if auth is None:
            auth=self.auth

        return self.client.users.get_users(_request_options={"headers": auth}).result()[0]

    def get_user(self, uid, auth=None):
        if auth is None:
            auth=self.auth

        return self.client.users.get_users_id(id=uid, _request_options={"headers": auth}).result()[0]

    def create_user(self, user, auth=None):
        if auth is None:
            auth=self.auth

        return self.client.users.post_users(user=user, _request_options={"headers": auth}).result()

    def delete_user(self, user_id, auth=None, headers={}):
        if auth is None:
            auth=self.auth

        headers['Authorization'] = auth['Authorization']
        # bravado for some reason doesn't issue DELETEs properly (silent failure)
        rsp = requests.delete(self.make_api_url('/users/{}'.format(user_id)), headers=headers)
        return rsp


class CliClient:
    cmd = '/testing/useradm'

    def create_user(self, name, pwd, user_id=None, tenant_id=None):
        args = [self.cmd,
                'create-user',
                '--username', name,
                '--password', pwd]

        if user_id is not None:
            args.extend(['--user-id', user_id])

        if tenant_id is not None:
            args.extend(['--tenant-id', tenant_id])

        subprocess.run(args, check=True)
