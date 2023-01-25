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

// Package kernels implements a unified view of the kernels in multiple backends
package kernels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"google3/third_party/notebookkernelsmixer/backends/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

// APIPath is the URL path to the kernels collection in the Jupyter REST API.
const APIPath = "/api/kernels"

// UnifiedView takes the backend view of the kernel and returns the global view.
func UnifiedView(k *resources.Kernel, b *backends.Backend) *resources.Kernel {
	if k == nil {
		return nil
	}
	localSpecID := k.SpecID
	unifiedSpecID := b.UnifiedID(localSpecID)
	return &resources.Kernel{
		ID:             k.ID,
		SpecID:         unifiedSpecID,
		Env:            k.Env,
		LastActivity:   k.LastActivity,
		Connections:    k.Connections,
		ExecutionState: k.ExecutionState,
	}
}

// BackendView takes the global view of the kernel and returns the backend view.
func BackendView(k *resources.Kernel, bs []*backends.Backend) (*backends.Backend, *resources.Kernel, error) {
	unifiedSpecID := k.SpecID
	b, localSpecID, err := backends.ParseUnifiedID(unifiedSpecID, bs)
	if err != nil {
		return nil, nil, fmt.Errorf("Failure resolving the backend view for the kernelspec %q: %w", unifiedSpecID, err)
	}
	return b, &resources.Kernel{
		ID:             k.ID,
		SpecID:         localSpecID,
		Env:            k.Env,
		LastActivity:   k.LastActivity,
		Connections:    k.Connections,
		ExecutionState: k.ExecutionState,
	}, nil
}

// Fetch returns the list of kernels for the given backend.
func Fetch(b *backends.Backend) ([]*resources.Kernel, error) {
	backendRespBytes, err := b.Get(APIPath)
	if err != nil {
		return nil, fmt.Errorf("failure reading the kernels from %q: %w", b.Name(), err)
	}
	var kernels []*resources.Kernel
	if err := json.Unmarshal(backendRespBytes, &kernels); err != nil {
		return nil, fmt.Errorf("failure parsing the kernels response from %q: %w", b.Name(), err)
	}
	return kernels, nil
}

type kernelsRecords struct {
	kernelsToBackendsMap map[string]*backends.Backend
	sync.Mutex
}

func (k *kernelsRecords) updateKernels(kernels []*resources.Kernel, backend *backends.Backend) {
	k.Lock()
	defer k.Unlock()
	for _, kernel := range kernels {
		k.kernelsToBackendsMap[kernel.ID] = backend
	}
}

func (k *kernelsRecords) fetchKernels(backend *backends.Backend) ([]*resources.Kernel, error) {
	kernels, err := Fetch(backend)
	if err != nil {
		return nil, err
	}
	k.updateKernels(kernels, backend)
	return kernels, err
}

func (k *kernelsRecords) findBackend(kernelID string) (*backends.Backend, error) {
	k.Lock()
	defer k.Unlock()
	b, ok := k.kernelsToBackendsMap[kernelID]
	if !ok {
		return nil, fmt.Errorf("unknown kernel %q: %w", kernelID, util.HTTPError(http.StatusNotFound))
	}
	return b, nil
}

func (k *kernelsRecords) recordKernel(kernelID string, backend *backends.Backend) {
	k.Lock()
	defer k.Unlock()
	k.kernelsToBackendsMap[kernelID] = backend
}

// combined takes the backend views of the kernels for both local and remote backends, and returns the global view of all kernels.
func (k *kernelsRecords) combined(localBackend *backends.Backend, remoteBackend *backends.Backend) ([]*resources.Kernel, error) {
	localKernels, err := k.fetchKernels(localBackend)
	if err != nil {
		return nil, fmt.Errorf("failure fetching the local kernels: %w", err)
	}
	remoteKernels, err := k.fetchKernels(remoteBackend)
	if err != nil {
		return nil, fmt.Errorf("failure fetching the remote kernels: %w", err)
	}
	unified := []*resources.Kernel{}
	for _, kernel := range localKernels {
		unified = append(unified, UnifiedView(kernel, localBackend))
	}
	for _, kernel := range remoteKernels {
		unified = append(unified, UnifiedView(kernel, remoteBackend))
	}
	return unified, nil
}

// Handler returns an HTTP handler that implements the global, combined kernels collection.
func Handler(localBackend *backends.Backend, remoteBackend *backends.Backend) http.Handler {
	bs := []*backends.Backend{localBackend, remoteBackend}
	kernelsRecords := &kernelsRecords{kernelsToBackendsMap: make(map[string]*backends.Backend)}
	go func() {
		kernelsRecords.fetchKernels(localBackend)
		kernelsRecords.fetchKernels(remoteBackend)
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativePath := strings.TrimPrefix(r.URL.Path, APIPath)
		relativePath = strings.TrimPrefix(relativePath, "/")
		if relativePath == "" && r.Method == http.MethodGet {
			// List the kernels
			unifiedKernels, err := kernelsRecords.combined(localBackend, remoteBackend)
			if err != nil {
				errorMsg := fmt.Sprintf("failure fetching the kernels: %v", err)
				http.Error(w, errorMsg, util.HTTPStatusCode(err))
				util.Log(r, fmt.Sprintf("Failed kernels API call: %q", errorMsg))
				return
			}
			respBytes, err := json.Marshal(unifiedKernels)
			if err != nil {
				errorMsg := fmt.Sprintf("failure marshalling the kernels collection: %v", err)
				http.Error(w, errorMsg, util.HTTPStatusCode(err))
				util.Log(r, fmt.Sprintf("Failed kernels API call: %q", errorMsg))
				return
			}
			w.Write(respBytes)
			return
		}
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errorMsg := fmt.Sprintf("failure reading in the request body: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		var backend *backends.Backend
		if relativePath != "" {
			// Forward the request directly to the backend
			kernelID := strings.Split(relativePath, "/")[0]
			backend, err = kernelsRecords.findBackend(kernelID)
			if err != nil {
				util.Log(r, err.Error())
				http.Error(w, err.Error(), util.HTTPStatusCode(err))
				return
			}
		}
		var backendFromBody *backends.Backend
		if len(bodyBytes) > 0 {
			var backendKernel *resources.Kernel
			var unifiedKernel resources.Kernel
			if err := json.Unmarshal(bodyBytes, &unifiedKernel); err != nil {
				errorMsg := fmt.Sprintf("failure parsing the body of a kernel request: %v", err)
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, http.StatusBadRequest)
				return
			}
			backendFromBody, backendKernel, err = BackendView(&unifiedKernel, bs)
			if err != nil {
				errorMsg := fmt.Sprintf("failure processing a kernel request: %v", err)
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, http.StatusBadRequest)
				return
			}
			backendReqBody, err := json.Marshal(backendKernel)
			if err != nil {
				errorMsg := fmt.Sprintf("failure marshalling the backend request: %v", err)
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, util.HTTPStatusCode(err))
				return
			}
			r.Body.Close()
			r.Body = ioutil.NopCloser(bytes.NewReader(backendReqBody))
			r.Header.Del("Content-Length")
			r.ContentLength = int64(len(backendReqBody))
		}
		if backend != nil && backendFromBody != nil && backend != backendFromBody {
			util.Log(r, fmt.Sprintf("Mismatch between backend from kernels API path and request body %q", string(bodyBytes)))
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if backend == nil {
			backend = backendFromBody
		}
		if backend == nil {
			util.Log(r, "Programming error: backend is nil. This should not happen")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if websocket.IsWebSocketUpgrade(r) {
			util.Log(r, fmt.Sprintf("Forwarding a websocket upgrade request: %+v", r))
			backend.ServeHTTP(w, r)
			return
		}
		r.Header.Del("Accept-Encoding")
		rr := httptest.NewRecorder()
		backend.ServeHTTP(rr, r)
		backendResp := rr.Result()
		for key, val := range backendResp.Header {
			if key != "Content-Length" {
				w.Header()[key] = val
			}
		}
		backendRespBytes, err := ioutil.ReadAll(backendResp.Body)
		backendResp.Body.Close()
		if err != nil {
			errorMsg := fmt.Sprintf("failure reading the backend response from %q: %v", backend.Name(), err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		if backendResp.StatusCode < http.StatusOK || backendResp.StatusCode >= http.StatusMultipleChoices {
			// For anything other than a 2XX response to one of the Swagger URLs, we don't modify the response
			w.WriteHeader(backendResp.StatusCode)
			if backendResp.StatusCode >= http.StatusBadRequest {
				util.Log(r, fmt.Sprintf("Error response %d from %q for %+v", backendResp.StatusCode, backend.Name(), r))
			}
			w.Write(backendRespBytes)
			return
		}
		var respBytes []byte
		if len(backendRespBytes) > 0 {
			var kernel resources.Kernel
			if err := json.Unmarshal(backendRespBytes, &kernel); err != nil {
				errorMsg := fmt.Sprintf("failure parsing the backend response from %q for %+v: %v, %q", backend.Name(), r, err, string(backendRespBytes))
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, util.HTTPStatusCode(err))
				return
			}
			unifiedKernel := UnifiedView(&kernel, backend)
			kernelsRecords.recordKernel(unifiedKernel.ID, backend)
			var err error
			respBytes, err = json.Marshal(unifiedKernel)
			if err != nil {
				errorMsg := fmt.Sprintf("failure marshalling the response: %v", err)
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, util.HTTPStatusCode(err))
				return
			}
		}
		w.WriteHeader(backendResp.StatusCode)
		w.Write(respBytes)
	})
}
