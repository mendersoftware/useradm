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
import json
import pytest
from pymongo import MongoClient
from base64 import b64encode
from client import CliClient, ManagementApiClient

def make_auth(sub, tenant=None):
    """
        Prepare an almost-valid JWT token header, suitable for consumption by our identity middleware (needs sub and optionally mender.tenant claims).

        The token contains valid base64-encoded payload, but the header/signature are bogus.
        This is enough for the identity middleware to interpret the identity
        and select the correct db; note that there is no gateway in the test setup, so the signature
        is never verified.

        If 'tenant' is specified, the 'mender.tenant' claim is added.
    """
    payload = {"sub": sub}
    if tenant is not None:
        payload["mender.tenant"] = tenant
    payload = json.dumps(payload)
    payloadb64 = b64encode(payload.encode("utf-8"))

    jwt = "bogus_header." + payloadb64.decode() + ".bogus_sign"

    return {"Authorization": "Bearer " + jwt}

def make_basic_auth(username, password):
    """
    Creates an auth header suitable for user /login.
    """
    hdr = "{}:{}".format(username, password)
    hdr = b64encode(hdr.encode("utf-8"))
    return "Basic " + hdr.decode()


@pytest.fixture(scope="session")
def mongo():
    return MongoClient('mender-mongo-useradm:27017')

def mongo_cleanup(mongo):
    dbs = mongo.database_names()
    dbs = [d for d in dbs if d not in ['local', 'admin']]
    for d in dbs:
        mongo.drop_database(d)

@pytest.fixture(scope="session")
def cli():
    return CliClient()

@pytest.fixture(scope="session")
def api_client_mgmt():
    return ManagementApiClient()

@pytest.yield_fixture(scope="class")
def init_users(cli, api_client_mgmt, mongo):
    for i in range(5):
        cli.create_user("user-{}@foo.com".format(i), "correcthorsebatterystaple")

    yield api_client_mgmt.get_users()
    mongo_cleanup(mongo)

@pytest.yield_fixture(scope="class")
def init_users_mt(cli, api_client_mgmt, mongo):
    tenant_users = {'tenant1id':[], 'tenant2id':[]}
    for t in tenant_users:
        for i in range(5):
            cli.create_user("user-{}-{}@foo.com".format(i,t), "correcthorsebatterystaple", None, t)
            tenant_users[t] = api_client_mgmt.get_users(make_auth("foo", t))
    yield tenant_users
    mongo_cleanup(mongo)
