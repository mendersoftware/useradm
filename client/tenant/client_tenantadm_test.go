// Copyright 2016 Mender Software AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/useradm/client/testing"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{TenantAdmAddr: "http://foo"})
	assert.NotNil(t, c)
}

func TestGetTenant(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		status    int
		inTenants []Tenant
		tenant    *Tenant
		err       error
	}{

		"ok": {
			status: http.StatusOK,
			inTenants: []Tenant{
				{
					ID:   "1234",
					Name: "tenant",
				},
			},

			tenant: &Tenant{
				ID:   "1234",
				Name: "tenant",
			},
			err: nil,
		},
		"ok - tenant not found": {
			// note no 404 here
			status:    http.StatusOK,
			inTenants: []Tenant{},
			tenant:    nil,
			err:       nil,
		},
		"error: generic": {
			status: http.StatusInternalServerError,
			err:    errors.New("GET /tenants request failed with unexpected status 500"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("name %v", name), func(t *testing.T) {
			t.Parallel()

			s, rd := ct.NewMockServer(tc.status, tc.inTenants)

			c := NewClient(Config{
				TenantAdmAddr: s.URL,
			})

			tenant, err := c.GetTenant(context.Background(), "username", &apiclient.HttpApi{})
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, GetTenantsUri, rd.Url.Path)
				assert.Equal(t, "GET", rd.Method)
				assert.Equal(t, tc.tenant, tenant)
			}
			s.Close()
		})
	}
}
