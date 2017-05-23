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
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/pkg/errors"
)

const (
	// devices endpoint
	GetTenantsUri = "/api/internal/v1/tenantadm/tenants"
	// default request timeout, 10s
	defaultReqTimeout = time.Duration(10) * time.Second
)

// ClientConfig conveys client configuration
type Config struct {
	// tenantadm  service address
	TenantAdmAddr string
	// request timeout
	Timeout time.Duration
}

// ClientRunner is an interface of tenantadm api client
type ClientRunner interface {
	GetTenant(ctx context.Context, username string, client apiclient.HttpRunner) (*Tenant, error)
}

// Client is an opaque implementation of tenantadm api client.
// Implements ClientRunner interface
type Client struct {
	conf Config
}

// Tenant is the tenantadm's api struct
type Tenant struct {
	ID   string
	Name string
}

func NewClient(conf Config) *Client {
	if conf.Timeout == 0 {
		conf.Timeout = defaultReqTimeout
	}

	return &Client{
		conf: conf,
	}
}

func (c *Client) GetTenant(ctx context.Context, username string, client apiclient.HttpRunner) (*Tenant, error) {
	req, err := http.NewRequest(http.MethodGet,
		JoinURL(c.conf.TenantAdmAddr, GetTenantsUri+"?username="+username),
		nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request to tenantadm")
	}

	ctx, cancel := context.WithTimeout(ctx, c.conf.Timeout)
	defer cancel()

	rsp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "GET /tenants request failed")
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("GET /tenants request failed with unexpected status %v", rsp.StatusCode)
	}

	tenants := []Tenant{}
	if err := json.NewDecoder(rsp.Body).Decode(&tenants); err != nil {
		return nil, errors.Wrap(err, "error parsing GET /tenants response")
	}

	switch len(tenants) {
	case 1:
		return &tenants[0], nil
	case 0:
		return nil, nil
	default:
		return nil, errors.Errorf("got unexpected number of tenants: %v", len(tenants))
	}
}

func JoinURL(base, url string) string {
	if strings.HasPrefix(url, "/") {
		url = url[1:]
	}
	if !strings.HasSuffix(base, "/") {
		base = base + "/"
	}
	return base + url
}
