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
package backends

import (
	"net/http"
	"testing"

	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

const (
	testBackendName        = "backendname"
	testResourceNameSuffix = " (Test Backend)"
	testResponseContents   = "OK"
)

var testHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if err := util.CheckXSRF(r); err != nil {
		http.Error(w, err.Error(), util.HTTPStatusCode(err))
	}
	switch method := r.Method; method {
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		w.Write([]byte(testResponseContents))
	case http.MethodPatch:
		w.Write([]byte(testResponseContents))
	case http.MethodPost:
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(testResponseContents))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
})

var testBackend *Backend = New(testBackendName, testResourceNameSuffix, "[::1]", testHandler)

func TestName(t *testing.T) {
	if got, want := testBackend.Name(), testBackendName; got != want {
		t.Errorf("testBackend.Name: got %q, want %q", got, want)
	}
}

func TestUnifiedName(t *testing.T) {
	if got, want := testBackend.UnifiedName("resource-name"), "resource-name"+testResourceNameSuffix; got != want {
		t.Errorf("testBackend.UnifiedName: got %q, want %q", got, want)
	}
}

func TestUnifiedID(t *testing.T) {
	if got, want := testBackend.UnifiedID("resource-id"), testBackendName+"-resource-id"; got != want {
		t.Errorf("testBackend.UnifiedID: got %q, want %q", got, want)
	}
}

func TestParseUnifiedID(t *testing.T) {
	localID := "resource-id"
	unifiedID := testBackend.UnifiedID(localID)
	if backend, parsedLocalID, err := ParseUnifiedID(unifiedID, []*Backend{testBackend}); err != nil {
		t.Errorf("ParseUnifiedID, unexpected error: %v", err)
	} else if got, want := backend, testBackend; got != want {
		t.Errorf("ParseUnifiedID, unexpected parsed backend: got %v, want %v", got, want)
	} else if got, want := parsedLocalID, localID; got != want {
		t.Errorf("ParseUnifiedID, unexpected parsed local ID: got %v, want %v", got, want)
	}

	if b, id, err := ParseUnifiedID(localID, []*Backend{testBackend}); err == nil {
		t.Errorf("ParseUnifiedID, unexpected response to an invalid call: got %+v, %q", b, id)
	}
}

func TestBackendGet(t *testing.T) {
	if bs, err := testBackend.Get("/"); err != nil {
		t.Errorf("Unexpected error in Backend.Get: %v", err)
	} else if got, want := string(bs), testResponseContents; got != want {
		t.Errorf("Unexpected response from Backend.Get: got %q, want %q", got, want)
	}
}

func TestBackendCreate(t *testing.T) {
	if bs, err := testBackend.Create("/", nil); err != nil {
		t.Errorf("Unexpected error in Backend.Create: %v", err)
	} else if got, want := string(bs), testResponseContents; got != want {
		t.Errorf("Unexpected response from Backend.Create: got %q, want %q", got, want)
	}
}

func TestBackendPatch(t *testing.T) {
	if bs, err := testBackend.Patch("/", nil); err != nil {
		t.Errorf("Unexpected error in Backend.Patch: %v", err)
	} else if got, want := string(bs), testResponseContents; got != want {
		t.Errorf("Unexpected response from Backend.Patch: got %q, want %q", got, want)
	}
}

func TestBackendDelete(t *testing.T) {
	if err := testBackend.Delete("/"); err != nil {
		t.Errorf("Unexpected error in Backend.Delete: %v", err)
	}
}
