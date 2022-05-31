// Copyright 2022 Northern.tech AS
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
package jwt

import "time"

// Token wrapper
type Token struct {
	Claims `bson:"inline"`
	// LastUsed is the token last usage timestamp.
	LastUsed *time.Time `json:"last_used,omitempty" bson:"last_used,omitempty"`
	// TokenName holds the name of the token
	TokenName *string `json:"name,omitempty" bson:"name,omitempty"`
}
