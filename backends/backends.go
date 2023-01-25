/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package backends provides utilities for communicating with backend Jupyter API servers.
package backends

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

// Backend is a wrapper around a Jupyter API server.
type Backend struct {
	name               string
	resourceNameSuffix string
	host               string
	handler            http.Handler
}

// New returns a new instance of Backend.
func New(backendName string, resourceNameSuffix string, host string, proxy http.Handler) *Backend {
	return &Backend{
		name:               backendName,
		resourceNameSuffix: resourceNameSuffix,
		host:               host,
		handler:            proxy,
	}
}

// Name returns the name of the backend.
func (b *Backend) Name() string {
	return b.name
}

// ServeHTTP implements the http.Handler interface.
func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.handler.ServeHTTP(w, r)
}

func (b *Backend) generateXSRFToken(r *http.Request) {
	xsrfTokTime := time.Now()
	xsrfTokHash := sha256.Sum256([]byte(b.name + xsrfTokTime.String()))
	xsrfTok := fmt.Sprintf("2|%x|%x|%d", xsrfTokHash[:4], xsrfTokHash[4:20], xsrfTokTime.Unix())
	r.AddCookie(&http.Cookie{
		Name:  "_xsrf",
		Value: xsrfTok,
	})
	r.Header.Add("X-XSRFToken", xsrfTok)
}

// Get returns the contents (as a slice of bytes) of the resource at the given URL path.
func (b *Backend) Get(path string) ([]byte, error) {
	r, err := http.NewRequest(http.MethodGet, path, strings.NewReader(""))
	if err != nil {
		return nil, fmt.Errorf("failure creating a backend request: %w", err)
	}
	r.Host = b.host
	rr := httptest.NewRecorder()
	b.handler.ServeHTTP(rr, r)
	backendResp := rr.Result()
	backendRespBytes, err := ioutil.ReadAll(backendResp.Body)
	backendResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failure reading the backend response from %q: %w", b.name, err)
	}
	if backendResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", util.HTTPError(backendResp.StatusCode), string(backendRespBytes))
	}
	return backendRespBytes, err
}

// Create inserts a new resource at the given URL path with the given contents.
func (b *Backend) Create(path string, body []byte) ([]byte, error) {
	r, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failure sending a backend create request: %w", err)
	}
	b.generateXSRFToken(r)
	rr := httptest.NewRecorder()
	b.handler.ServeHTTP(rr, r)
	resp := rr.Result()
	respBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failure reading the backend create response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%w: %s", util.HTTPError(resp.StatusCode), string(respBytes))
	}
	return respBytes, nil
}

// Patch updates a new resource at the given URL path with the given contents.
func (b *Backend) Patch(path string, body []byte) ([]byte, error) {
	r, err := http.NewRequest(http.MethodPatch, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failure sending a backend create request: %w", err)
	}
	b.generateXSRFToken(r)
	rr := httptest.NewRecorder()
	b.handler.ServeHTTP(rr, r)
	resp := rr.Result()
	respBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failure reading the backend create response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", util.HTTPError(resp.StatusCode), string(respBytes))
	}
	return respBytes, nil
}

// Delete deletes the resource at the given URL path.
func (b *Backend) Delete(path string) error {
	r, err := http.NewRequest(http.MethodDelete, path, strings.NewReader(""))
	if err != nil {
		return fmt.Errorf("failure creating the backend delete request: %w", err)
	}
	b.generateXSRFToken(r)
	rr := httptest.NewRecorder()
	b.handler.ServeHTTP(rr, r)
	resp := rr.Result()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failure reading the body for a backend delete response with status %v: %w", resp.StatusCode, err)
	}
	return fmt.Errorf("%w: %s", util.HTTPError(resp.StatusCode), string(respBytes))
}

// UnifiedID takes a resource ID that is specific to the backend and returns an ID that is globally unique.
func (b *Backend) UnifiedID(localID string) string {
	return b.name + "-" + localID
}

// UnifiedName takes the name for a resource in either the remote or local backend and returns a name that is appropriate for the combination of both backends.
func (b *Backend) UnifiedName(localName string) string {
	return localName + b.resourceNameSuffix
}

// ParseUnifiedID takes a resource ID that is globally unique and returns one that is specific to either the remote or local backend.
func ParseUnifiedID(id string, backends []*Backend) (b *Backend, localID string, err error) {
	for _, b := range backends {
		if strings.HasPrefix(id, b.name+"-") {
			localID := strings.TrimPrefix(id, b.name+"-")
			return b, localID, nil
		}
	}
	return nil, "", fmt.Errorf("invalid unified ID: %q: %w", id, util.HTTPError(http.StatusBadRequest))
}
