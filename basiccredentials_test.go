// Copyright 2026 The Alpaca Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeBasicSecretStore struct {
	service, username, password string
	getErr, setErr              error
}

func (s *fakeBasicSecretStore) Get(service, username string) (string, error) {
	s.service = service
	s.username = username
	return s.password, s.getErr
}

func (s *fakeBasicSecretStore) Set(service, username, password string) error {
	s.service = service
	s.username = username
	s.password = password
	return s.setErr
}

func TestBasicAuthenticatorFromKeyring(t *testing.T) {
	store := &fakeBasicSecretStore{password: "secret"}
	auth, err := basicAuthenticatorFromKeyring("alice", store)
	require.NoError(t, err)
	assert.Equal(t, basicKeyringService, store.service)
	assert.Equal(t, "alice", store.username)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("alice:secret")), auth.encoded)
}

func TestBasicAuthenticatorFromKeyringRequiresUsername(t *testing.T) {
	auth, err := basicAuthenticatorFromKeyring("", &fakeBasicSecretStore{})
	assert.Nil(t, auth)
	assert.EqualError(t, err, "basic proxy username is empty")
}

func TestBasicAuthenticatorFromKeyringReturnsStoreError(t *testing.T) {
	auth, err := basicAuthenticatorFromKeyring("alice", &fakeBasicSecretStore{
		getErr: errors.New("missing"),
	})
	assert.Nil(t, auth)
	assert.ErrorContains(t, err, "missing")
}

func TestStoreBasicCredentials(t *testing.T) {
	store := &fakeBasicSecretStore{}
	require.NoError(t, storeBasicCredentials("alice", "secret", store))
	assert.Equal(t, basicKeyringService, store.service)
	assert.Equal(t, "alice", store.username)
	assert.Equal(t, "secret", store.password)
}

func TestStoreBasicCredentialsReturnsStoreError(t *testing.T) {
	err := storeBasicCredentials("alice", "secret", &fakeBasicSecretStore{
		setErr: errors.New("denied"),
	})
	assert.ErrorContains(t, err, "denied")
}
