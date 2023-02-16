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
package jupytertestutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
)

func TestRoundtrip(t *testing.T) {
	server := httptest.NewServer(DefaultMockJupyter)
	defer server.Close()

	var ks *resources.KernelSpecs
	if err := Get(server, "/api/kernelspecs", &ks); err != nil {
		t.Fatalf("Failed to get the initial kernelspecs: %v", err)
	}
	if ks.Default == "" {
		t.Fatalf("Mock Jupyter had no default kernelspec")
	}
	if _, ok := ks.KernelSpecs[ks.Default]; !ok {
		t.Fatalf("Mock Jupyter had a missing default kernelspec")
	}
	k1 := &resources.Kernel{
		SpecID: ks.Default,
	}
	var k2 resources.Kernel
	if err := Post(server, "/api/kernels", k1, &k2); err != nil {
		t.Fatalf("Failure posting the initial kernel: %v", err)
	}
	if got, want := k1.SpecID, k2.SpecID; got != want {
		t.Errorf("Unexpected saved kernelspec: got %q, want %q", got, want)
	}
	var k3 resources.Kernel
	if err := Get(server, "/api/kernels/"+k2.ID, &k3); err != nil {
		t.Errorf("Failure reading back the inserted kernel: %v", err)
	} else if got, want := k3.ID, k2.ID; got != want {
		t.Errorf("Unexpected inserted kernel ID: got %q, want %q", got, want)
	} else if got, want := k3.SpecID, k2.SpecID; got != want {
		t.Errorf("Unexpected inserted kernelspec ID: got %q, want %q", got, want)
	}
	var kc1 []resources.Kernel
	if err := Get(server, "/api/kernels", &kc1); err != nil {
		t.Errorf("Failure reading the kernels collection: %v", err)
	} else if got, want := len(kc1), 1; got != want {
		t.Errorf("Unexpected number of kernels: got %d, want %d", got, want)
	}
	if err := ExerciseKernelWebsockets(server.URL, "", k2.ID, http.Header{}); err != nil {
		t.Errorf("Failure exercising the kernel: %v", err)
	}

	var kc2 []resources.Kernel
	if err := Delete(server, "/api/kernels/"+k2.ID); err != nil {
		t.Errorf("Failure deleting the kernel: %v", err)
	} else if err := Get(server, "/api/kernels", &kc2); err != nil {
		t.Errorf("Failure reading the post-delete kernels collection: %v", err)
	} else if got, want := len(kc2), 0; got != want {
		t.Errorf("Unexpected number of kernels: got %d, want %d", got, want)
	}

	s1 := &resources.Session{
		Kernel: &resources.Kernel{
			SpecID: ks.Default,
		},
	}
	var s2, s3 resources.Session
	var sc []*resources.Session
	if err := Post(server, "/api/sessions", s1, &s2); err != nil {
		t.Errorf("Failure posting the initial session: %v", err)
	} else if got, want := s1.Kernel.SpecID, s2.Kernel.SpecID; got != want {
		t.Errorf("Unexpected inserted session kernelspec: got %q, want %q", got, want)
	} else if err := Get(server, "/api/sessions/"+s2.ID, &s3); err != nil {
		t.Errorf("Failure reading back the inserted session: %v", err)
	} else if got, want := s3.Kernel.SpecID, s2.Kernel.SpecID; got != want {
		t.Errorf("Unexpected saved session kernelspec: got %q, want %q", got, want)
	} else if got, want := s3.Kernel.ID, s2.Kernel.ID; got != want {
		t.Errorf("Unexpected saved session kernel ID: got %q, want %q", got, want)
	} else if err := Get(server, "/api/sessions", &sc); err != nil {
		t.Errorf("Failure listing the saved sessions: %v", err)
	} else if got, want := len(sc), 1; got != want {
		t.Errorf("Unexpected number of sessions: got %d, want %d", got, want)
	}

	s3.Name = "example.ipynb"
	var s4 resources.Session
	if err := Patch(server, "/api/sessions/"+s3.ID, &s3, &s4); err != nil {
		t.Errorf("Failure patching the saved session: %v", err)
	} else if got, want := s4.Name, s3.Name; got != want {
		t.Errorf("Unexpected saved session name: got %q, want %q", got, want)
	}
	var sc2 []resources.Session
	if err := Delete(server, "/api/sessions/"+s4.ID); err != nil {
		t.Errorf("Failure deleting the session: %v", err)
	} else if err := Get(server, "/api/sessions", &sc2); err != nil {
		t.Errorf("Failure reading the post-delete sessions collection: %v", err)
	} else if got, want := len(sc2), 0; got != want {
		t.Errorf("Unexpected number of sessions: got %d, want %d", got, want)
	}
}
