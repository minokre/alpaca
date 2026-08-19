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
	"errors"
	"fmt"

	ring "github.com/zalando/go-keyring"
)

const basicKeyringService = "alpaca-basic"

type basicSecretStore interface {
	Get(service, username string) (string, error)
	Set(service, username, password string) error
}

type systemBasicSecretStore struct{}

func (systemBasicSecretStore) Get(service, username string) (string, error) {
	return ring.Get(service, username)
}

func (systemBasicSecretStore) Set(service, username, password string) error {
	return ring.Set(service, username, password)
}

func basicAuthenticatorFromKeyring(username string, store basicSecretStore) (
	*basicAuthenticator, error,
) {
	if username == "" {
		return nil, errors.New("basic proxy username is empty")
	}
	password, err := store.Get(basicKeyringService, username)
	if err != nil {
		return nil, fmt.Errorf("cannot get Basic proxy password from keyring: %w", err)
	}
	return newBasicAuthenticator(username + ":" + password), nil
}

func storeBasicCredentials(username, password string, store basicSecretStore) error {
	if username == "" {
		return errors.New("basic proxy username is empty")
	}
	if err := store.Set(basicKeyringService, username, password); err != nil {
		return fmt.Errorf("cannot store Basic proxy password in keyring: %w", err)
	}
	return nil
}
