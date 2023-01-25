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
package util

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestModifyURLHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", strings.NewReader(""))
	testPath := "/some/path"
	testHost := "example.com"
	req.Header.Add("Origin", "http://localhost"+testPath)

	if err := IfHeaderIsURLThenChangeHost(req, "Origin", testHost); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	originURL, err := url.Parse(req.Header.Get("Origin"))
	if err != nil {
		t.Fatalf("Malformed URL in origin header: %v", err)
	}
	if got, want := originURL.Scheme, "https"; got != want {
		t.Errorf("Unexpected scheme in origin header: got %q, want %q", got, want)
	}
	if got, want := originURL.Host, testHost; got != want {
		t.Errorf("Unexpected host in origin header: got %q, want %q", got, want)
	}
	if got, want := originURL.Path, testPath; got != want {
		t.Errorf("Unexpected path in origin header: got %q, want %q", got, want)
	}
}

func TestModifyProxiedRequestForHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", strings.NewReader(""))
	testPath := "/some/path"
	testRefererPath := "/some/path"
	testHost := "example.com"
	req.Header.Add("Origin", "http://localhost"+testPath)
	req.Header.Add("Referer", "http://localhost"+testRefererPath)

	if errs := ModifyProxiedRequestForHost(req, testHost); len(errs) != 0 {
		t.Fatalf("Unexpected errors: %v", errs)
	}
	originURL, err := url.Parse(req.Header.Get("Origin"))
	if err != nil {
		t.Fatalf("Malformed URL in origin header: %v", err)
	}
	if got, want := originURL.Scheme, "https"; got != want {
		t.Errorf("Unexpected scheme in origin header: got %q, want %q", got, want)
	}
	if got, want := originURL.Host, testHost; got != want {
		t.Errorf("Unexpected host in origin header: got %q, want %q", got, want)
	}
	if got, want := originURL.Path, testPath; got != want {
		t.Errorf("Unexpected path in origin header: got %q, want %q", got, want)
	}
	refererURL, err := url.Parse(req.Header.Get("Referer"))
	if err != nil {
		t.Fatalf("Malformed URL in referer header: %v", err)
	}
	if got, want := refererURL.Scheme, "https"; got != want {
		t.Errorf("Unexpected scheme in referer header: got %q, want %q", got, want)
	}
	if got, want := refererURL.Host, testHost; got != want {
		t.Errorf("Unexpected host in referer header: got %q, want %q", got, want)
	}
	if got, want := refererURL.Path, testRefererPath; got != want {
		t.Errorf("Unexpected path in referer header: got %q, want %q", got, want)
	}
	if got, want := req.Host, testHost; got != want {
		t.Errorf("Unexpected host in request: got %q, want %q", got, want)
	}
}

func TestHTTPStatusCode(t *testing.T) {
	testCases := []struct {
		Description string
		Error       error
		Want        int
	}{
		{
			Description: "Raw error",
			Error:       errors.New("error that does not wrap an HTTPError"),
			Want:        http.StatusInternalServerError,
		},
		{
			Description: "HTTPError error",
			Error:       HTTPError(http.StatusConflict),
			Want:        http.StatusConflict,
		},
		{
			Description: "Wrapped HTTPError error",
			Error:       fmt.Errorf("a wrapped error: %w", HTTPError(http.StatusConflict)),
			Want:        http.StatusConflict,
		},
		{
			Description: "Deeply wrapped HTTPError error",
			Error:       fmt.Errorf("an outer wrapper: %w", fmt.Errorf("a wrapped error: %w", HTTPError(http.StatusConflict))),
			Want:        http.StatusConflict,
		},
	}
	for _, testCase := range testCases {
		if got, want := HTTPStatusCode(testCase.Error), testCase.Want; got != want {
			t.Errorf("Unexpected HTTP status code for %q: got %d, want %d", testCase.Description, got, want)
		}
	}
}

func TestIsUserError(t *testing.T) {
	testCases := []struct {
		Description string
		Error       error
		Want        bool
	}{
		{
			Description: "Raw error",
			Error:       errors.New("error that does not wrap an HTTPError"),
			Want:        false,
		},
		{
			Description: "Nil error",
			Error:       nil,
			Want:        false,
		},
		{
			Description: "OK response",
			Error:       HTTPError(http.StatusOK),
			Want:        false,
		},
		{
			Description: "Bad request response",
			Error:       HTTPError(http.StatusBadRequest),
			Want:        true,
		},
		{
			Description: "Forbidden response",
			Error:       HTTPError(http.StatusForbidden),
			Want:        true,
		},
		{
			Description: "Internal server error",
			Error:       HTTPError(http.StatusInternalServerError),
			Want:        false,
		},
	}
	for _, testCase := range testCases {
		if got, want := IsUserError(testCase.Error), testCase.Want; got != want {
			t.Errorf("Unexpected result from `IsUserError` for %q: got %t, want %t", testCase.Description, got, want)
		}
	}
}

func TestCheckXSRF(t *testing.T) {
	postNoCookie := httptest.NewRequest("POST", "/", nil)
	postNoCookie.Header.Set("X-XSRFToken", "xsrf")
	postNoHeader := httptest.NewRequest("POST", "/", nil)
	postNoHeader.AddCookie(&http.Cookie{Name: "_xsrf", Value: "xsrf"})
	postHeaderAndCookie := httptest.NewRequest("POST", "/", nil)
	postHeaderAndCookie.Header.Set("X-XSRFToken", "xsrf")
	postHeaderAndCookie.AddCookie(&http.Cookie{Name: "_xsrf", Value: "xsrf"})

	testCases := []struct {
		Description    string
		Request        *http.Request
		WantError      bool
		WantStatusCode int
	}{
		{
			Description: "GET requests do not require XSRF headers",
			Request:     httptest.NewRequest("GET", "/", nil),
			WantError:   false,
		},
		{
			Description: "HEAD requests do not require XSRF headers",
			Request:     httptest.NewRequest("HEAD", "/", nil),
			WantError:   false,
		},
		{
			Description:    "POST requests do require XSRF headers",
			Request:        httptest.NewRequest("POST", "/", nil),
			WantError:      true,
			WantStatusCode: http.StatusForbidden,
		},
		{
			Description:    "PATCH requests do require XSRF headers",
			Request:        httptest.NewRequest("PATCH", "/", nil),
			WantError:      true,
			WantStatusCode: http.StatusForbidden,
		},
		{
			Description:    "DELETE requests do require XSRF headers",
			Request:        httptest.NewRequest("DELETE", "/", nil),
			WantError:      true,
			WantStatusCode: http.StatusForbidden,
		},
		{
			Description:    "POST requests do require an _xsrf cookie",
			Request:        postNoCookie,
			WantError:      true,
			WantStatusCode: http.StatusForbidden,
		},
		{
			Description:    "POST requests do require an X-XSRFToken header",
			Request:        postNoHeader,
			WantError:      true,
			WantStatusCode: http.StatusForbidden,
		},
		{
			Description: "POST requests with both a cookie and header are allowed",
			Request:     postHeaderAndCookie,
			WantError:   false,
		},
	}
	for _, testCase := range testCases {
		gotError := CheckXSRF(testCase.Request)
		if got, want := (gotError != nil), testCase.WantError; got != want {
			t.Errorf("Unexpected result from `CheckXSRF` for %q: got error %t, want error %t", testCase.Description, got, want)
			continue
		}
		if !testCase.WantError {
			continue
		}
		if got, want := HTTPStatusCode(gotError), testCase.WantStatusCode; got != want {
			t.Errorf("Unexpected HTTP status code for %q: got %d, want %d", testCase.Description, got, want)
		}
	}
}

func TestLoggingResponseWriter(t *testing.T) {
	testResponseHeader := "X-Logging-Response-Writer-Header"
	testResponseHeaderValue := "test-response-header-value"
	testResponseBody := "CREATED"

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr1 := httptest.NewRecorder()
	lwr1 := NewLoggingResponseWriter(rr1, req1, nil)
	lwr1.Header().Set(testResponseHeader, testResponseHeaderValue)
	lwr1.Write([]byte("OK"))
	req1ID := req1.Header.Get("X-Mixer-Request-ID")
	if req1ID == "" {
		t.Errorf("Unexpectedly missing request ID for %+v", req1)
	}
	resp1 := rr1.Result()
	if got, want := resp1.Header.Get(testResponseHeader), testResponseHeaderValue; got != want {
		t.Errorf("Unexpected response header value for %q: got %q, want %q", testResponseHeader, got, want)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	rr2 := httptest.NewRecorder()
	var resp2Buff bytes.Buffer
	lwr2 := NewLoggingResponseWriter(rr2, req2, &resp2Buff)
	lwr2.Header().Set(testResponseHeader, testResponseHeaderValue)
	lwr2.WriteHeader(http.StatusCreated)
	lwr2.Write([]byte(testResponseBody))
	resp2 := rr2.Result()
	if got, want := resp2.StatusCode, http.StatusCreated; got != want {
		t.Errorf("Unexpected response status code: got %d, want %d", got, want)
	}
	if got, want := resp2.Header.Get(testResponseHeader), testResponseHeaderValue; got != want {
		t.Errorf("Unexpected response header value for %q in second request: got %q, want %q", testResponseHeader, got, want)
	}
	if readBody, err := io.ReadAll(resp2.Body); err != nil {
		t.Errorf("Unexpected error reading a response body: %v", err)
	} else if got, want := string(readBody), testResponseBody; got != want {
		t.Errorf("Unexpected response body: got %q, want %q", got, want)
	}
	if loggedBody := resp2Buff.String(); loggedBody != testResponseBody {
		t.Errorf("Unexpected logged response body: got %q, want %q", loggedBody, testResponseBody)
	}
}
