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

// Package jupytertestutil contains utilities for mockign and testing Jupyter backend requests.
package jupytertestutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

type mockJupyter struct {
	basePath      string
	kernelspecs   *resources.KernelSpecs
	injectErrors  bool
	injectLatency time.Duration

	// mu protects the fields below it.
	mu sync.Mutex

	firstCalledTime time.Time
	lastCalledPath  string
	kernels         map[string]*resources.Kernel
	sessions        map[string]*resources.Session
}

// NewMockJupyter returns a new HTTP handler that implements a mock Jupyter backend server.
func NewMockJupyter(basePath string, injectErrors bool, injectLatency time.Duration, kernelspecs *resources.KernelSpecs) http.Handler {
	return &mockJupyter{
		basePath:      basePath,
		kernelspecs:   kernelspecs,
		injectErrors:  injectErrors,
		injectLatency: injectLatency,
		kernels:       make(map[string]*resources.Kernel),
		sessions:      make(map[string]*resources.Session),
	}
}

// DefaultKernelSpecs is a hard-coded KernelSpecs instance with a single kernelspec.
var DefaultKernelSpecs *resources.KernelSpecs = &resources.KernelSpecs{
	Default: "python3",
	KernelSpecs: map[string]*resources.KernelSpec{
		"python3": &resources.KernelSpec{
			ID: "python3",
			Spec: &resources.Spec{
				Language:    "python",
				DisplayName: "Python",
			},
			Resources: map[string]string{
				"example": "example.jpg",
			},
		},
	},
}

// DefaultMockJupyter is an HTTP handler that implements a mock Jupyter server with one kernelspec.
var DefaultMockJupyter http.Handler = NewMockJupyter("", false, 0, DefaultKernelSpecs)

func (m *mockJupyter) relativePath(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, m.basePath)
}

func (m *mockJupyter) recordURL(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastCalledPath != r.URL.Path {
		m.lastCalledPath = r.URL.Path
		m.firstCalledTime = time.Now()
	}
}

func (m *mockJupyter) handleKernelspecsRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	if m.relativePath(r) != "/api/kernelspecs" {
		http.Error(w, fmt.Sprintf("Path not supported: %q", m.relativePath(r)), http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
		return
	}
	resp, err := json.Marshal(m.kernelspecs)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal kernelspecs: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (m *mockJupyter) insertKernel(k *resources.Kernel) (*resources.Kernel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kernelspecs.KernelSpecs[k.SpecID]; !ok {
		return nil, fmt.Errorf("unknown kernelspec %q: %w", k.SpecID, util.HTTPError(http.StatusBadRequest))
	}
	k.ID = uuid.New().String()
	m.kernels[k.ID] = k
	return k, nil
}

func (m *mockJupyter) getKernel(w http.ResponseWriter, r *http.Request, kernelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.kernels[kernelID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	resp, err := json.Marshal(k)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal kernel: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (m *mockJupyter) deleteKernel(w http.ResponseWriter, r *http.Request, kernelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kernels[kernelID]; !ok {
		http.NotFound(w, r)
		return
	}
	delete(m.kernels, kernelID)
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockJupyter) handleKernelsRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	if strings.HasPrefix(m.relativePath(r), "/api/kernels/") {
		kernelID := strings.TrimPrefix(m.relativePath(r), "/api/kernels/")
		switch method := r.Method; method {
		case http.MethodGet:
			m.getKernel(w, r, kernelID)
			return
		case http.MethodDelete:
			m.deleteKernel(w, r, kernelID)
			return
		default:
			http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
			return
		}
	}
	switch method := r.Method; method {
	case http.MethodPost:
		var k resources.Kernel
		if err := json.Unmarshal(body, &k); err != nil {
			http.Error(w, fmt.Sprintf("malformed kernel resource: %q, %v", string(body), err), http.StatusBadRequest)
			return
		}
		saved, err := m.insertKernel(&k)
		if err != nil {
			http.Error(w, err.Error(), util.HTTPStatusCode(err))
			return
		}
		resp, err := json.Marshal(saved)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshal kernel: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(resp)
		return
	case http.MethodGet:
		m.mu.Lock()
		defer m.mu.Unlock()
		var kc []*resources.Kernel
		for _, k := range m.kernels {
			kc = append(kc, k)
		}
		resp, err := json.Marshal(kc)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshal kernels: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	default:
		http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
	}
}

func (m *mockJupyter) insertSession(s *resources.Session) (*resources.Session, error) {
	k, err := m.insertKernel(s.Kernel)
	if err != nil {
		return nil, err
	}
	var inserted resources.Session = *s
	inserted.Kernel = k
	inserted.ID = uuid.New().String()
	if path, ok := inserted.Notebook["path"]; ok {
		inserted.Path = path
	}
	if len(inserted.Path) > 0 {
		inserted.Notebook["path"] = inserted.Path
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[inserted.ID] = &inserted
	return &inserted, nil
}

func (m *mockJupyter) getSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	resp, err := json.Marshal(s)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal session: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (m *mockJupyter) deleteSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if sess.Kernel == nil {
		w.WriteHeader(http.StatusNoContent)
	}
	m.deleteKernel(w, r, sess.Kernel.ID)
	return
}

func (m *mockJupyter) updateSession(w http.ResponseWriter, r *http.Request, sessionID string, s *resources.Session) {
	var updated resources.Session = *s
	if path, ok := updated.Notebook["path"]; ok {
		updated.Path = path
	}
	if len(updated.Path) > 0 {
		updated.Notebook["path"] = updated.Path
	}
	m.mu.Lock()
	orig, ok := m.sessions[sessionID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	m.mu.Unlock()
	if orig.Kernel != nil && (updated.Kernel == nil || orig.Kernel.ID != updated.Kernel.ID) {
		delete(m.kernels, orig.Kernel.ID)
		orig.Kernel = nil
	}
	if orig.Kernel == nil && updated.Kernel != nil {
		inserted, err := m.insertKernel(updated.Kernel)
		if err != nil {
			http.Error(w, err.Error(), util.HTTPStatusCode(err))
			return
		}
		updated.Kernel = inserted
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = &updated
	resp, err := json.Marshal(&updated)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal session: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (m *mockJupyter) handleSessionsRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	if strings.HasPrefix(m.relativePath(r), "/api/sessions/") {
		sessionID := strings.TrimPrefix(m.relativePath(r), "/api/sessions/")
		switch method := r.Method; method {
		case http.MethodGet:
			m.getSession(w, r, sessionID)
			return
		case http.MethodDelete:
			m.deleteSession(w, r, sessionID)
			return
		case http.MethodPatch:
			var s resources.Session
			if err := json.Unmarshal(body, &s); err != nil {
				http.Error(w, fmt.Sprintf("malformed session resource: %q, %v", string(body), err), http.StatusBadRequest)
			}
			m.updateSession(w, r, sessionID, &s)
			return
		default:
			http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
			return
		}
	}
	switch method := r.Method; method {
	case http.MethodPost:
		var s resources.Session
		if err := json.Unmarshal(body, &s); err != nil {
			http.Error(w, fmt.Sprintf("malformed session resource: %q, %v", string(body), err), http.StatusBadRequest)
		}
		saved, err := m.insertSession(&s)
		if err != nil {
			http.Error(w, err.Error(), util.HTTPStatusCode(err))
			return
		}
		resp, err := json.Marshal(saved)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshal session: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(resp)
	case http.MethodGet:
		m.mu.Lock()
		defer m.mu.Unlock()
		var sc []*resources.Session
		for _, s := range m.sessions {
			sc = append(sc, s)
		}
		resp, err := json.Marshal(sc)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshal kernels: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	default:
		http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
	}
}

func (m *mockJupyter) shouldFailRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !m.injectErrors {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastCalledPath != r.URL.Path {
		return true
	}
	return time.Since(m.firstCalledTime) < time.Second
}

func (m *mockJupyter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer m.recordURL(r)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Inject artificial latency on mutation requests to simulate real-world performance.
		time.Sleep(m.injectLatency)
	}
	if m.shouldFailRequest(r) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failure reading request body: %v", err), http.StatusInternalServerError)
	}
	switch collection := strings.Split(strings.TrimPrefix(m.relativePath(r), "/api/"), "/")[0]; collection {
	case "kernelspecs":
		m.handleKernelspecsRequest(w, r, body)
	case "kernels":
		m.handleKernelsRequest(w, r, body)
	case "sessions":
		m.handleSessionsRequest(w, r, body)
	default:
		http.Error(w, fmt.Sprintf("Method not supported for path %q", m.relativePath(r)), http.StatusBadRequest)
	}
}

// Get issues a GET request to the test server at the given path, and then deserializes the response into the supplied `out` parameter.
func Get(server *httptest.Server, path string, out any) error {
	resp, err := server.Client().Get(server.URL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("failure parsing the GET response %q: %w", string(respBytes), err)
	}
	return nil
}

// AddXSRFHeaderAndCookie adds an XSRF token header and cookie in the format expected by Jupyter.
func AddXSRFHeaderAndCookie(r *http.Request, token string) {
	xsrfTokTime := time.Now()
	xsrfTokHash := sha256.Sum256([]byte(token + xsrfTokTime.String()))
	xsrfTok := fmt.Sprintf("2|%x|%x|%d", xsrfTokHash[:4], xsrfTokHash[4:20], xsrfTokTime.Unix())
	r.AddCookie(&http.Cookie{
		Name:  "_xsrf",
		Value: xsrfTok,
	})
	r.Header.Add("X-XSRFToken", xsrfTok)
}

// Post issues a POST request to the test server at the given path, with a serialized form of the supplied `res` parameter.
//
// It then deserializes the response into the supplied `out` parameter.
func Post(server *httptest.Server, path string, res any, out any) error {
	reqBytes, err := json.Marshal(res)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	AddXSRFHeaderAndCookie(req, "xsrf-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("failure parsing the POST response %q: %w", string(respBytes), err)
	}
	return nil
}

// Patch issues a PATCH request to the test server at the given path, with a serialized form of the supplied `res` parameter.
//
// It then deserializes the response into the supplied `out` parameter.
func Patch(server *httptest.Server, path string, res any, out any) error {
	reqBytes, err := json.Marshal(res)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPatch, server.URL+path, bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	AddXSRFHeaderAndCookie(req, "xsrf-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("failure parsing the PATCH response %q: %w", string(respBytes), err)
	}
	return nil
}

// Delete issues a DELETE request to the test server at the given path.
func Delete(server *httptest.Server, path string) error {
	req, err := http.NewRequest(http.MethodDelete, server.URL+path, nil)
	if err != nil {
		return err
	}
	AddXSRFHeaderAndCookie(req, "xsrf-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code for a delete: %w", util.HTTPError(resp.StatusCode))
	}
	return nil
}
