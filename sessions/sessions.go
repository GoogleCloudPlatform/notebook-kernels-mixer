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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/kernels"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

// APIPath is the URL path to the sessions collection in the Jupyter REST API.
const APIPath = "/api/sessions"

func fillInMissingFields(saved, partial *resources.Session) {
	if partial.ID == "" {
		partial.ID = saved.ID
	}
	if partial.Notebook == nil {
		partial.Notebook = saved.Notebook
	}
	if partial.Notebook != nil {
		if len(partial.Path) > 0 {
			partial.Notebook["path"] = partial.Path
		}
		if path, ok := partial.Notebook["path"]; ok {
			partial.Path = path
		}
	}
	if partial.Path == "" {
		partial.Path = saved.Path
	}
	if partial.Name == "" {
		partial.Name = saved.Name
	}
	if partial.Type == "" {
		partial.Type = saved.Type
	}
	if partial.Kernel == nil {
		partial.Kernel = saved.Kernel
	}
}

// UnifiedView takes the backend view of the session and returns the global view.
func UnifiedView(s *resources.Session, b *backends.Backend, sessionID string) *resources.Session {
	if s == nil {
		return nil
	}
	newSess := *s
	newSess.ID = sessionID
	newSess.Kernel = kernels.UnifiedView(s.Kernel, b)
	return &newSess
}

// fetchSessions returns the list of sessions for the given backend.
func fetchSessions(b *backends.Backend) ([]*resources.Session, error) {
	backendRespBytes, err := b.Get(APIPath)
	if err != nil {
		return nil, fmt.Errorf("failure reading the sessions from %q: %w", b.Name(), err)
	}
	var sessions []*resources.Session
	if err := json.Unmarshal(backendRespBytes, &sessions); err != nil {
		return nil, fmt.Errorf("failure parsing the sessions response from %q: %w", b.Name(), err)
	}
	return sessions, nil
}

type sessionRecord struct {
	backend     *backends.Backend
	backendView *resources.Session
}

func (r *sessionRecord) UnifiedView(sessionID string) *resources.Session {
	return UnifiedView(r.backendView, r.backend, sessionID)
}

type collection struct {
	localBackend      *backends.Backend
	remoteBackend     *backends.Backend
	sessionsMap       map[string]*sessionRecord
	sessionUnifiedIDs map[string]string
	sync.Mutex
}

func newCollection(localBackend, remoteBackend *backends.Backend) *collection {
	return &collection{
		localBackend:      localBackend,
		remoteBackend:     remoteBackend,
		sessionsMap:       make(map[string]*sessionRecord),
		sessionUnifiedIDs: make(map[string]string),
	}
}

func (s *collection) Update() error {
	s.Lock()
	defer s.Unlock()
	localSessions, err := fetchSessions(s.localBackend)
	if err != nil {
		return fmt.Errorf("failure listing the local sessions: %w", err)
	}
	remoteSessions, err := fetchSessions(s.remoteBackend)
	if err != nil {
		// We don't treat failures communicating with the remote backend as terminal,
		// and instead simply treat the sessions hosted there as being lost. If the
		// remote backend becomes available again we will rediscover the remote sessions
		// at that point.
		log.Printf("failure listing the remote sessions: %v", err)
		remoteSessions = nil
	}
	updatedSessions := make(map[string]*sessionRecord)
	for _, session := range localSessions {
		if session.ID == "" {
			// Ignore incomplete sessions from the backend
			continue
		}
		unifiedID, ok := s.sessionUnifiedIDs[session.ID]
		if !ok {
			unifiedID = session.ID
			s.sessionUnifiedIDs[session.ID] = unifiedID
		}
		updatedSessions[unifiedID] = &sessionRecord{
			backend:     s.localBackend,
			backendView: session,
		}
	}
	for _, session := range remoteSessions {
		if session.ID == "" {
			// Ignore incomplete sessions from the backend
			continue
		}
		unifiedID, ok := s.sessionUnifiedIDs[session.ID]
		if !ok {
			unifiedID = session.ID
			s.sessionUnifiedIDs[session.ID] = unifiedID
		}
		updatedSessions[unifiedID] = &sessionRecord{
			backend:     s.remoteBackend,
			backendView: session,
		}
	}
	s.sessionsMap = updatedSessions
	return nil
}

func (s *collection) Get(unifiedID string) (*resources.Session, bool) {
	s.Lock()
	defer s.Unlock()
	record, ok := s.sessionsMap[unifiedID]
	if !ok {
		return nil, false
	}
	if unified := record.UnifiedView(unifiedID); unified != nil {
		return unified, true
	}
	return nil, false
}

func (s *collection) List() []*resources.Session {
	s.Lock()
	defer s.Unlock()
	sessions := []*resources.Session{}
	for sessionID, record := range s.sessionsMap {
		if unified := record.UnifiedView(sessionID); unified != nil {
			sessions = append(sessions, unified)
		}
	}
	return sessions
}

func (s *collection) Insert(unifiedID string, sess *resources.Session) (*resources.Session, error) {
	s.Lock()
	defer s.Unlock()
	return s.insertWithLock(unifiedID, sess)
}

func (s *collection) insertWithLock(unifiedID string, sess *resources.Session) (*resources.Session, error) {
	var backend *backends.Backend
	var backendK *resources.Kernel
	var err error
	if sess.Kernel != nil {
		backend, backendK, err = kernels.BackendView(sess.Kernel, []*backends.Backend{s.localBackend, s.remoteBackend})
		if err != nil {
			return nil, fmt.Errorf("failure converting the kernel: %w", err)
		}
	}
	// Pass through create session but return mapped session ID
	sess.Kernel = backendK
	sessBytes, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("failure marshalling session request: %w", err)
	}
	sessionRespBytes, err := backend.Create(APIPath, sessBytes)
	if err != nil {
		// Don't wrap the error from a backend; just report it exactly.
		return nil, err
	}
	var newSess resources.Session
	if err = json.Unmarshal(sessionRespBytes, &newSess); err != nil {
		return nil, fmt.Errorf("failure unmarshalling local session response: %w", err)
	}
	record := &sessionRecord{
		backend:     backend,
		backendView: &newSess,
	}
	if unifiedID == "" {
		// The unified ID of a session matches it's original backend session ID
		unifiedID = newSess.ID
	}
	s.sessionsMap[unifiedID] = record
	s.sessionUnifiedIDs[newSess.ID] = unifiedID
	return record.UnifiedView(unifiedID), nil
}

func (s *collection) Delete(unifiedID string) bool {
	s.Lock()
	defer s.Unlock()
	return s.deleteWithLock(unifiedID)
}

func (s *collection) deleteWithLock(unifiedID string) bool {
	record, ok := s.sessionsMap[unifiedID]
	if !ok {
		return false
	}
	backend := record.backend
	sessionPath := APIPath + "/" + record.backendView.ID
	if err := backend.Delete(sessionPath); err != nil {
		log.Printf("Failure trying to delete a kernel: %v", err)
		return false
	}
	delete(s.sessionsMap, unifiedID)
	delete(s.sessionUnifiedIDs, record.backendView.ID)
	return true
}

func (s *collection) Patch(r *http.Request, unifiedID string, sess *resources.Session) (*resources.Session, error) {
	s.Lock()
	defer s.Unlock()
	record, ok := s.sessionsMap[unifiedID]
	if !ok {
		return nil, fmt.Errorf("session %q not found: %w", unifiedID, util.HTTPError(http.StatusNotFound))
	}
	backend := record.backend
	var err error
	var k *resources.Kernel
	if sess.Kernel != nil {
		backend, k, err = kernels.BackendView(sess.Kernel, []*backends.Backend{s.localBackend, s.remoteBackend})
		if err != nil {
			err = fmt.Errorf("failure converting the session kernel: %w", err)
			util.Log(r, err)
			return nil, err
		}
		sess.Kernel = k
	}
	fillInMissingFields(record.backendView, sess)
	if record.backend != backend {
		// Change in location; delete the old session and create a new one.
		s.deleteWithLock(unifiedID)
		return s.insertWithLock(unifiedID, UnifiedView(sess, backend, ""))
	}
	// The backend is unchanged, so simply forward the patch request to it.
	sess.ID = record.backendView.ID
	reqBytes, err := json.Marshal(sess)
	if err != nil {
		err = fmt.Errorf("failure marshalling the updated session: %w", err)
		util.Log(r, err)
		return nil, err
	}
	respBytes, err := backend.Patch("/api/sessions/"+sess.ID, reqBytes)
	if err != nil {
		err = fmt.Errorf("failure patching the session: %w", err)
		util.Log(r, err)
		return nil, err
	}
	var resp resources.Session
	if err = json.Unmarshal(respBytes, &resp); err != nil {
		err = fmt.Errorf("failure unmarshalling the patched session: %w", err)
		util.Log(r, err)
		return nil, err
	}
	record.backendView = &resp
	return record.UnifiedView(unifiedID), nil
}

// Handler implements the sessions collection.
func Handler(localBackend *backends.Backend, remoteBackend *backends.Backend) http.Handler {
	// Sessions and kernels within the session map are in their backend form
	sessions := newCollection(localBackend, remoteBackend)
	go func() {
		for {
			if err := sessions.Update(); err != nil {
				log.Printf("Failure updating the sessions list: %v", err)
			}
			time.Sleep(30 * time.Second)
		}
	}()
	getMethod := func(w http.ResponseWriter, r *http.Request) {
		sessionID := strings.TrimPrefix(r.URL.Path, APIPath+"/")
		sess, ok := sessions.Get(sessionID)
		if !ok {
			http.NotFound(w, r)
			return
		}
		resp, err := json.Marshal(&sess)
		if err != nil {
			util.Log(r, fmt.Sprintf("Failure marshalling the session response: %v", err))
			http.Error(w, "failure marshalling the session", util.HTTPStatusCode(err))
			return
		}
		w.Write(resp)
	}
	listMethod := func(w http.ResponseWriter, r *http.Request) {
		resp, err := json.Marshal(sessions.List())
		if err != nil {
			util.Log(r, fmt.Sprintf("Failure marshalling the list sessions response: %v", err))
			http.Error(w, "failure marshalling the list of sessions", util.HTTPStatusCode(err))
			return
		}
		w.Write(resp)
	}
	insertMethod := func(w http.ResponseWriter, r *http.Request) {
		reqBytes, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			errorMsg := fmt.Sprintf("failure reading the request body: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		var sess resources.Session
		if err := json.Unmarshal(reqBytes, &sess); err != nil {
			errorMsg := fmt.Sprintf("failure parsing the request body: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		util.Log(r, fmt.Sprintf("Creating a new kernel for the session: %q", string(reqBytes)))
		newSession, err := sessions.Insert("", &sess)
		if err != nil {
			util.Log(r, err)
			http.Error(w, err.Error(), util.HTTPStatusCode(err))
			return
		}
		respBytes, err := json.Marshal(newSession)
		if err != nil {
			errorMsg := fmt.Sprintf("failure marshalling session response: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(respBytes)
	}
	deleteMethod := func(w http.ResponseWriter, r *http.Request) {
		sessionID := strings.TrimPrefix(r.URL.Path, APIPath+"/")
		if ok := sessions.Delete(sessionID); !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	patchMethod := func(w http.ResponseWriter, r *http.Request) {
		subPath := strings.TrimPrefix(r.URL.Path, APIPath+"/")
		sessionID := strings.Split(subPath, "/")[0]
		reqBytes, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			errorMsg := fmt.Sprintf("failure reading the request body: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		var sess resources.Session
		if err := json.Unmarshal(reqBytes, &sess); err != nil {
			errorMsg := fmt.Sprintf("failure parsing the request body: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, http.StatusBadRequest)
			return
		}
		updatedSession, err := sessions.Patch(r, sessionID, &sess)
		if err != nil {
			errorMsg := fmt.Sprintf("failure patching the session: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		respBytes, err := json.Marshal(updatedSession)
		if err != nil {
			errorMsg := fmt.Sprintf("failure marshalling the return session: %v", err)
			util.Log(r, errorMsg)
			http.Error(w, errorMsg, util.HTTPStatusCode(err))
			return
		}
		util.Log(r, fmt.Sprintf("Updated session: %q\n", string(respBytes)))
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.URL.Path == APIPath {
				listMethod(w, r)
			} else {
				getMethod(w, r)
			}
			return
		}
		if r.URL.Path == APIPath {
			if r.Method != http.MethodPost {
				errorMsg := fmt.Sprintf("unsupported method %q", r.Method)
				util.Log(r, errorMsg)
				http.Error(w, errorMsg, http.StatusMethodNotAllowed)
				return
			}
			insertMethod(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			deleteMethod(w, r)
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			patchMethod(w, r)
			return
		}
		errorMsg := fmt.Sprintf("unsupported method %q", r.Method)
		util.Log(r, errorMsg)
		http.Error(w, errorMsg, http.StatusMethodNotAllowed)
	})
}
