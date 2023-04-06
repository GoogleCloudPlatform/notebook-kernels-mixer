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

// Package sessions implements a unified view of the sessions across multiple backends.
package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/jupytertestutil"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
	"google3/webutil/http/go/httpheader"
)

func TestFillInMissingFields(t *testing.T) {
	var fullSession, partialSession resources.Session
	fullSession.ID = "testID"
	fullSession.Path = "/some/test/notebook/path"
	fullSession.Name = "test-notebook.ipynb"
	fullSession.Type = "notebook"
	fullSession.Kernel = &resources.Kernel{
		ID:     "test-kernel",
		SpecID: "test-spec",
	}
	fullSession.Notebook = map[string]string{
		"a": "b",
		"c": "d",
	}
	fillInMissingFields(&fullSession, &partialSession)
	if diff := cmp.Diff(fullSession, partialSession, cmpopts.IgnoreUnexported(resources.Session{}, resources.Kernel{})); len(diff) > 0 {
		t.Errorf("Unexpected diff for the result of the session.fillInMissingFields method: %s", diff)
	}
}

func NewSessionsRequest(method, urlPath string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, urlPath, body)
	if err != nil {
		return nil, fmt.Errorf("internal error creating a test request: %w", err)
	}
	r.Header.Add(httpheader.Authorization, "Bearer 42")
	r.Host = "sample-project-dot-us-central1.notebook-kernels"
	return r, nil
}

func GetSession(handler http.Handler, sessionID string) (*resources.Session, error) {
	sessionPath := path.Join(APIPath, sessionID)
	r, err := NewSessionsRequest(http.MethodGet, sessionPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failure getting a session: %w", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	respBytes, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		return nil, fmt.Errorf("failure reading the get session response for %q: %w", sessionID, err)
	}
	var result resources.Session
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failure parsing the get session response for %q, %q: %w", sessionID, string(respBytes), err)
	}
	return &result, nil
}

func ListSessions(handler http.Handler) ([]*resources.Session, error) {
	r, err := NewSessionsRequest(http.MethodGet, APIPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failure listing sessions: %w", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	respBytes, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		return nil, fmt.Errorf("failure reading the list sessions response: %w", err)
	}
	var result []*resources.Session
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failure parsing the list sessions response %q: %w", string(respBytes), err)
	}
	return result, nil
}

func CreateSession(handler http.Handler, sess *resources.Session) (*resources.Session, error) {
	sessBytes, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("failure marshalling the session %+v: %v", sess, err)
	}
	r, err := NewSessionsRequest(http.MethodPost, APIPath, bytes.NewReader(sessBytes))
	if err != nil {
		return nil, fmt.Errorf("failure creating a session: %w", err)
	}
	jupytertestutil.AddXSRFHeaderAndCookie(r, "abcdefg")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if got, want := rr.Result().StatusCode, http.StatusCreated; got != want {
		respBody, err := io.ReadAll(rr.Result().Body)
		if err != nil {
			return nil, fmt.Errorf("failure reading the create session response: %v", err)
		}
		return nil, fmt.Errorf("unexpected response code when creating the session; got %d, want %d, resp %q", got, want, respBody)
	}
	respBytes, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		return nil, fmt.Errorf("failure reading the create session response: %v", err)
	}
	var result resources.Session
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failure parsing the create session response %q: %v", string(respBytes), err)
	}
	return &result, nil
}

func UpdateSession(handler http.Handler, sessionID string, sess *resources.Session) (*resources.Session, error) {
	sessionPath := path.Join(APIPath, sessionID)
	sessBytes, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("failure marshalling the session %+v: %v", sess, err)
	}
	r, err := NewSessionsRequest(http.MethodPatch, sessionPath, bytes.NewReader(sessBytes))
	if err != nil {
		return nil, fmt.Errorf("failure updating a session: %w", err)
	}
	jupytertestutil.AddXSRFHeaderAndCookie(r, "abcdefg")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	respBytes, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		return nil, fmt.Errorf("failure reading the patch session response for %q: %v", sessionID, err)
	}
	var result resources.Session
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failure parsing the patch session response for %q, %q: %v", sessionID, string(respBytes), err)
	}
	return &result, nil
}

func DeleteSession(handler http.Handler, sessionID string) error {
	sessionPath := path.Join(APIPath, sessionID)
	r, err := NewSessionsRequest(http.MethodDelete, sessionPath, nil)
	if err != nil {
		return fmt.Errorf("failure deleting a session: %w", err)
	}
	jupytertestutil.AddXSRFHeaderAndCookie(r, "abcdefg")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if got, want := rr.Result().StatusCode, http.StatusNoContent; got != want {
		return fmt.Errorf("unexpected response code when deleting the session %q; got %d, want %d", sessionID, got, want)
	}
	return nil
}

func diffSessions(got, want *resources.Session, opts ...cmp.Option) string {
	opts = append(opts, cmpopts.IgnoreUnexported(resources.Kernel{}, resources.Session{}))
	return cmp.Diff(got, want, opts...)
}

func TestCreateUpdateDelete(t *testing.T) {
	localMockJupyter := httptest.NewServer(jupytertestutil.NewMockJupyter("", false, 0, 0, jupytertestutil.DefaultKernelSpecs))
	defer localMockJupyter.Close()
	localURL, err := url.Parse(localMockJupyter.URL)
	if err != nil {
		t.Fatalf("failure parsing the URL of the mock local jupyter: %v", err)
	}
	remoteMockJupyter := httptest.NewServer(jupytertestutil.NewMockJupyter("", false, 0, 0, jupytertestutil.DefaultKernelSpecs))
	defer remoteMockJupyter.Close()
	remoteURL, err := url.Parse(remoteMockJupyter.URL)
	if err != nil {
		t.Fatalf("failure parsing the URL of the mock remote jupyter: %v", err)
	}

	localBackend := backends.New("local", "(Local)", localURL.Hostname(), httputil.NewSingleHostReverseProxy(localURL))
	remoteBackend := backends.New("remote", "(Remote)", remoteURL.Hostname(), httputil.NewSingleHostReverseProxy(remoteURL))
	sessionsHandler := Handler(localBackend, remoteBackend)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// repeatedly list sessions in the background to check for data races in concurrent reads...
	errs := make(chan error, 1000)
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(errs)
				return
			default:
				if listed, err := ListSessions(sessionsHandler); err != nil {
					errs <- fmt.Errorf("failure listing sessions in the background: %w", err)
				} else if _, err := json.Marshal(listed); err != nil {
					errs <- fmt.Errorf("failure marshalling the listed sessions: %w", err)
				}
			}
		}
	}()
	if listed, err := ListSessions(sessionsHandler); err != nil {
		t.Errorf("failure listing the sessions: %v", err)
	} else if len(listed) != 0 {
		t.Errorf("unexpected response to list sessions: %v", listed)
	}

	initialSession := &resources.Session{
		Path: uuid.New().String(),
		Name: "example.ipynb",
		Type: "notebook",
		Kernel: &resources.Kernel{
			SpecID: "local-python3",
		},
		Notebook: map[string]string{
			"a": "A",
			"b": "B",
		},
	}

	// Test creating a session.
	saved, err := CreateSession(sessionsHandler, initialSession)
	if err != nil {
		t.Fatalf("failure creating a sessions: %v", err)
	} else if saved.ID == "" {
		t.Fatalf("failed to generate a session ID for the session %+v", saved)
	} else if saved.Kernel.ID == "" {
		t.Errorf("failed to generate a kernel ID for the session %+v", saved)
	}
	t.Logf("Created session: %+v", saved)

	// Test getting the created session.
	ignorePathMapDiff := cmpopts.IgnoreMapEntries(func(k, v string) bool { return k == "path" })
	if diff := diffSessions(saved, initialSession, cmpopts.IgnoreFields(resources.Session{}, "ID"), cmpopts.IgnoreFields(resources.Kernel{}, "ID", "LastActivity", "ExecutionState"), ignorePathMapDiff); diff != "" {
		t.Errorf("unexpected diff for constructed session: %+v, %s", saved, diff)
	} else if got, err := GetSession(sessionsHandler, saved.ID); err != nil {
		t.Errorf("failured getting a saved session %q: %v", saved.ID, err)
	} else if diff := diffSessions(saved, got); diff != "" {
		t.Errorf("unexpected diff when reading back the saved session %q: %s", saved.ID, diff)
	}

	// Test listing the created session.
	if listed, err := ListSessions(sessionsHandler); err != nil {
		t.Errorf("failure listing sessions: %v", err)
	} else if len(listed) != 1 {
		t.Errorf("unexpected response when listing sessions: %v", listed)
	} else if diff := diffSessions(listed[0], saved); diff != "" {
		t.Errorf("unexpected diff when listing the saved session %q: %s", saved.ID, diff)
	}

	// Test updating the session.
	partialUpdateSession := &resources.Session{
		Path: "/home/user/notebooks/updated-example.ipynb",
	}
	if updatedSession, err := UpdateSession(sessionsHandler, saved.ID, partialUpdateSession); err != nil {
		t.Errorf("failure updating a sessions: %v", err)
	} else if got, want := updatedSession.Path, partialUpdateSession.Path; got != want {
		t.Errorf("failed to perform a partial update on the session %q; got %q, want %q", saved.ID, got, want)
	} else if path, ok := updatedSession.Notebook["path"]; !ok {
		t.Errorf("notebook field for updated session unexpectedly missing: %+v", updatedSession)
	} else if got, want := path, partialUpdateSession.Path; got != want {
		t.Errorf("failed to perform a partial update on the notebook field of a session %q; got %q, want %q", saved.ID, got, want)
	} else if diff := diffSessions(updatedSession, saved, cmpopts.IgnoreFields(resources.Session{}, "Path"), ignorePathMapDiff); diff != "" {
		t.Errorf("unexpected diff when performing a partial update on the session %q, %s", saved.ID, diff)
	} else if listed, err := ListSessions(sessionsHandler); err != nil {
		t.Errorf("failure listing sessions: %v", err)
	} else if len(listed) != 1 {
		t.Errorf("unexpected response when listing sessions: %v", listed)
	} else if diff := diffSessions(listed[0], updatedSession); diff != "" {
		t.Errorf("unexpected diff when listing the updated session %q: %s", saved.ID, diff)
	}

	// Test updating the session.
	partialUpdateWithKernelSession := &resources.Session{
		Path: "/home/user/notebooks/second-updated-example.ipynb",
		Kernel: &resources.Kernel{
			SpecID: "remote-python3",
		},
	}
	updatedSession, err := UpdateSession(sessionsHandler, saved.ID, partialUpdateWithKernelSession)
	if err != nil {
		t.Errorf("failure updating a sessions: %v", err)
	} else if got, want := updatedSession.Path, partialUpdateWithKernelSession.Path; got != want {
		t.Errorf("failed to perform a partial update on the session %q; got %q, want %q", saved.ID, got, want)
	} else if path, ok := updatedSession.Notebook["path"]; !ok {
		t.Errorf("notebook field for updated session unexpectedly missing: %+v", updatedSession)
	} else if got, want := path, partialUpdateWithKernelSession.Path; got != want {
		t.Errorf("failed to perform a partial update on the notebook field of a session %q; got %q, want %q", saved.ID, got, want)
	} else if got, want := updatedSession.Kernel.SpecID, partialUpdateWithKernelSession.Kernel.SpecID; got != want {
		t.Errorf("failed to perform a partial update on the session %q; got %q, want %q", saved.ID, got, want)
	} else if diff := diffSessions(updatedSession, saved, cmpopts.IgnoreFields(resources.Session{}, "Path", "Kernel"), ignorePathMapDiff); diff != "" {
		t.Errorf("unexpected diff when performing a partial update on the session %q, %s", saved.ID, diff)
	} else if listed, err := ListSessions(sessionsHandler); err != nil {
		t.Errorf("failure listing sessions: %v", err)
	} else if bs, err := json.Marshal(listed); err != nil {
		t.Errorf("failure marshalling the listed sessions: %v", err)
	} else if len(listed) != 1 {
		t.Errorf("unexpected response when listing sessions: %q", string(bs))
	} else if diff := diffSessions(listed[0], updatedSession); diff != "" {
		t.Errorf("unexpected diff when listing the updated session %q: %s", saved.ID, diff)
	}

	// Test deleting the session and listing to make sure it is gone.
	if err := DeleteSession(sessionsHandler, saved.ID); err != nil {
		t.Errorf("failure deleting the session %q: %v", saved.ID, err)
	} else if listed, err := ListSessions(sessionsHandler); err != nil {
		t.Errorf("failure listing the sessions: %v", err)
	} else if bs, err := json.Marshal(listed); err != nil {
		t.Errorf("failure marshalling the listed sessions: %v", err)
	} else if len(listed) != 0 {
		t.Errorf("unexpected response when listing sessions: %q", string(bs))
	}

	cancel()
	for err := range errs {
		t.Log(err)
	}
}
