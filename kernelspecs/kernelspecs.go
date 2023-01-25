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

// Package kernelspecs contains utilities for fetching the unified view of kernelspecs from multiple backends.
package kernelspecs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"google3/third_party/notebookkernelsmixer/backends/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

// APIPath is the URL path to the kernelspecs collection in the Jupyter REST API.
const APIPath = "/api/kernelspecs"

// UnifiedView takes the backend view of the kernelspec and returns the global view.
func UnifiedView(ks *resources.KernelSpec, b *backends.Backend) *resources.KernelSpec {
	if ks == nil {
		return nil
	}
	localID := ks.ID
	unifiedID := b.UnifiedID(localID)
	unifiedSpec := *ks.Spec
	unifiedSpec.DisplayName = b.UnifiedName(unifiedSpec.DisplayName)
	unifiedView := &resources.KernelSpec{
		ID:        unifiedID,
		Spec:      &unifiedSpec,
		Resources: make(map[string]string),
	}
	for k, v := range ks.Resources {
		backendPathPrefix := "/kernelspecs/" + localID + "/"
		unifiedPathPrefix := "/kernelspecs/" + unifiedID + "/"
		if strings.HasPrefix(v, backendPathPrefix) {
			v = unifiedPathPrefix + strings.TrimPrefix(v, backendPathPrefix)
		}
		unifiedView.Resources[k] = v
	}
	return unifiedView
}

// fetchKernelSpecs takes a backend and returns the list of kernelspecs reported by that backend.
func fetchKernelSpecs(b *backends.Backend) (*resources.KernelSpecs, error) {
	backendRespBytes, err := b.Get(APIPath)
	if err != nil {
		return nil, fmt.Errorf("failure reading the kernelspecs from %q: %w", b.Name(), err)
	}
	var kernelSpecs resources.KernelSpecs
	if err := json.Unmarshal(backendRespBytes, &kernelSpecs); err != nil {
		return nil, fmt.Errorf("failure parsing the kernelspecs response from %q: %w", b.Name(), err)
	}
	return &kernelSpecs, nil
}

// CombinedKernelSpecs takes a backend views of the kernelspecs for both local and remote backends, and returns the combined global view of all kernelspecs.
func CombinedKernelSpecs(localBackend *backends.Backend, remoteBackend *backends.Backend) (*resources.KernelSpecs, error) {
	unifiedView := &resources.KernelSpecs{
		KernelSpecs: make(map[string]*resources.KernelSpec),
	}
	localKernelSpecs, err := fetchKernelSpecs(localBackend)
	if err != nil {
		return unifiedView, fmt.Errorf("failure fetching the local kernelspecs: %w", err)
	}
	remoteKernelSpecs, err := fetchKernelSpecs(remoteBackend)
	if err != nil {
		return unifiedView, fmt.Errorf("failure fetching the remote kernelspecs: %w", err)
	}
	if remoteKernelSpecs != nil && remoteKernelSpecs.Default != "" {
		unifiedView.Default = remoteBackend.UnifiedID(remoteKernelSpecs.Default)
		for id, spec := range remoteKernelSpecs.KernelSpecs {
			unifiedID := remoteBackend.UnifiedID(id)
			unifiedView.KernelSpecs[unifiedID] = UnifiedView(spec, remoteBackend)
		}
	}
	if localKernelSpecs != nil {
		if localKernelSpecs.Default != "" {
			unifiedView.Default = localBackend.UnifiedID(localKernelSpecs.Default)
		}
		for id, spec := range localKernelSpecs.KernelSpecs {
			unifiedID := localBackend.UnifiedID(id)
			unifiedView.KernelSpecs[unifiedID] = UnifiedView(spec, localBackend)
		}
	}
	return unifiedView, nil
}

// Handler returns an HTTP handler that implements the global, combined kernelspecs collection.
func Handler(localBackend *backends.Backend, remoteBackend *backends.Backend) http.Handler {
	bs := []*backends.Backend{localBackend, remoteBackend}
	resourcePath := "/kernelspecs/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errorMsg := fmt.Sprintf("unsupported method %v", r.Method)
			http.Error(w, errorMsg, http.StatusBadRequest)
			util.Log(r, errorMsg)
			return
		}
		if strings.HasPrefix(r.URL.Path, resourcePath) {
			subpath := strings.TrimPrefix(r.URL.Path, resourcePath)
			unifiedID := strings.Split(subpath, "/")[0]
			backend, localID, err := backends.ParseUnifiedID(unifiedID, bs)
			if err != nil {
				errorMsg := fmt.Sprintf("invalid kernelspec ID: %q", unifiedID)
				http.Error(w, errorMsg, http.StatusBadRequest)
				util.Log(r, fmt.Sprintf("Failure parsing a kernelspecs resource path: %q", errorMsg))
				return
			}
			localPath := strings.Replace(r.URL.Path, unifiedID, localID, 1)
			util.Log(r, fmt.Sprintf("Translated unified path %q into local path %q", r.URL.Path, localPath))
			r.URL.Path = localPath
			backend.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != APIPath {
			errorMsg := fmt.Sprintf("unsupported kernelspecs API endpoint: %q", r.URL.Path)
			http.Error(w, errorMsg, http.StatusBadRequest)
			util.Log(r, fmt.Sprintf("Failed kernelspecs API call: %q\n", errorMsg))
			return
		}
		unifiedKernelSpecs, err := CombinedKernelSpecs(localBackend, remoteBackend)
		if err != nil {
			errorMsg := fmt.Sprintf("failure fetching the kernelspecs: %v", err)
			util.Log(r, fmt.Sprintf("Failed kernelspecs API call: %q", errorMsg))
		}
		respBytes, err := unifiedKernelSpecs.MarshalJSON()
		if err != nil {
			errorMsg := fmt.Sprintf("failure marshalling the kernelspecs collection: %v", err)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			util.Log(r, fmt.Sprintf("Failed kernelspecs API call: %q", errorMsg))
			return
		}
		w.Write(respBytes)
	})
}
