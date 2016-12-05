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
package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSimpleAuthzAuthorize(t *testing.T) {
	// resource, action, (real) token
	// scope all, resource any
	// scope create user, diff resource
	// scope create, resource create
	// scope unknown
	//
	//
	privkey := loadPrivKey("crypto/private.pem", t)
	jwth := NewJWTHandlerRS256(privkey, nil)

	testCases := map[string]struct {
		inResource string
		inAction   string
		inToken    string

		outErr string
	}{
		"ok - create init user with dedicated scope": {
			inResource: "users:initial",
			inAction:   "POST",
			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
				"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik" +
				"1lbmRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiw" +
				"ic2NwIjoibWVuZGVyLnVzZXJzLmluaXRpYWwu" +
				"Y3JlYXRlIn0.vcg5XS81mZT9oFpFiPsU5KYz5" +
				"UAaSWnmlxopW5qsrcV3IQ4mODo63rqvZnfLgc" +
				"eBW3qfdmi025BLhiajtEGHhggXZdTD5Q_3q08" +
				"dqWFaePI42FzmAITqmzWAnNS78xUh0EZ3uNnz" +
				"RPPWDOV5IDpsJHtV44_vZ341dxssTWEsuSMxm" +
				"Jk8_VergMGQ8hJSk7_ioAP11kRCuKz1R5ruPS" +
				"kicrrw5Z9vmx86zFPLXhy98Jz3cuMKhy4npEu" +
				"3GhdTYhWIFv2_xwCFTEamWB1PQ7JVkNdjMHt7" +
				"9AxEXYoDxYpCWvjdeEXs7gVPFvMespq3fRGxw" +
				"IvgDV1UmL2nb9AlzkInJw",
		},
		"ok - do sth with the 'all' scope": {
			inResource: "some:resource:id",
			inAction:   "POST",
			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
				"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik" +
				"1lbmRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiw" +
				"ic2NwIjoibWVuZGVyLioifQ.s8IBgKnEvCMzw" +
				"ibDyjPaZolYie81YqdbuERlWh_izkZg8mBLEk" +
				"15D63VVcr6fsixz0S3T_96NLf2FAr0QkyPQYl" +
				"Rw5oXSCVIDLPlmtXXJ0ppy7tOlQVTzr9nP--V" +
				"g_9n8vjiH5-qc0zeae9PhtXBH0Xg_IoD1tj1Q" +
				"IFkEHw4WYO5bFbcNoh3iF0VKUxoHFcbR3wUAB" +
				"-EucgpGB_OvQha_OnNrRqvSgdtjF4xxgGWiA4" +
				"9tlWfwsQlnzyp7XEtn-s5RpNFxHHmWuGbcqN7" +
				"UxiYoGeoPiCGYDmThKv6435ew4DbAVz1XpDgf" +
				"Qzl0TKwig67gYuauSjQfrOVQwXyGzUQRQ",
		},
		"error: unknown/incompatible scope": {
			inResource: "users:initial",
			inAction:   "POST",
			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
				"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik" +
				"1lbmRlciIsInN1YiI6InRlc3RzdWJqZWN0Iiw" +
				"ic2NwIjoic29tZS5pbnZhbGlkLnNjb3BlIn0." +
				"VNkvs52FSJpFcacnqydoTmHdmOBjLq6OXbKLa" +
				"f6dR3iRxry-75Gan2j2ZtZqt2tq8bpf_lWRdh" +
				"kCCQcA542jrIkWrqvY_w632JDNh_2wyglG9R_" +
				"6Xitz31HVE-Wj4WQzmAQyl3my0DWiMn-dtbox" +
				"hp9jZfHUjYxJzus7fpRkkew0ckmiDS-ULFdAe" +
				"WBuAQHypVwtpCN7maFrWbATJ29We5T8QQpSi2" +
				"6RrW8I8NyXQE2YRR2mGoyHLjnEQdxJHV8U8xY" +
				"t8nde8Fe1NQVTeNz0tTgQyUByLPt2NpIBkb29" +
				"NA1ygq8umitZdh13m_gwNnFxAbrEGRlFLIIVK" +
				"TtzWorsZw",
			outErr: "unauthorized",
		},
		"error: invalid token": {
			inResource: "some:resource:id",
			inAction:   "POST",
			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjIxNDc0ODM2NDcsImp0aSI6IjEyM" +
				"zQ1NjciLCJpYXQiOjEyMzQ1NjcsImlzcyI6Ik",
			outErr: "invalid jwt",
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)

		authz := NewSimpleAuthz(jwth, nil)

		err := authz.Authorize(tc.inToken, tc.inResource, tc.inAction)

		if tc.outErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tc.outErr)
		}
	}
}
