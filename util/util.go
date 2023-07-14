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

// Package util provides utility methods for the notebookkernelsmixer codebase.
package util

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
)

const (
	requestIDHeader = "X-Mixer-Request-ID"
)

// IfHeaderIsURLThenChangeHost updates a request header containing a URL to specify the given host.
//
// More specifically, if the given header is present, then its value is parsed
// as a URL, the host of that URL is updated to the given target, and then the
// updated URL is written back to the request header.
//
// This is useful when forwarding requests via a reverse proxy, in order to
// ensure that certain headers, like `Origin` and `Referer`, match the
// hostname of the backend server.
//
// Those values need to be changed before the request is forwarded to the
// backend as the URL for the proxy will be different from the URL for each
// respective backend server.
func IfHeaderIsURLThenChangeHost(r *http.Request, name, targetHost string) error {
	if r.Header.Get(name) == "" {
		return nil
	}
	headerURL, err := url.Parse(r.Header.Get(name))
	if err != nil {
		return fmt.Errorf("malformed URL in header %q in proxied request: %q", name, r.Header.Get(name))
	}
	if headerURL.Host == r.Host {
		headerURL.Host = targetHost
		headerURL.Scheme = "https"
	}
	r.Header.Set(name, headerURL.String())
	return nil
}

// ModifyProxiedRequestForHost modifies a request so that it matches the given host.
//
// This is a helper method for reverse proxies that need to translate a
// request specific to the proxy into one that is specific to a backend host.
func ModifyProxiedRequestForHost(r *http.Request, targetHost string) []error {
	var errs []error
	if err := IfHeaderIsURLThenChangeHost(r, "Referer", targetHost); err != nil {
		errs = append(errs, err)
	}
	if err := IfHeaderIsURLThenChangeHost(r, "Origin", targetHost); err != nil {
		errs = append(errs, err)
	}
	r.Header.Del("Host")
	r.Host = targetHost
	return errs
}

// HTTPError implements the error type for an HTTP response status code.
//
// This is meant to be used as the base error that other errors wrap.
//
// Example Usage:
//
//	if resp.StatusCode != http.StatusOK {
//		return nil, fmt.Errorf("Some message: %w", util.HttpError(resp.StatusCode))
//	}
type HTTPError int

func (err HTTPError) Error() string {
	return fmt.Sprintf("%d %s", err.StatusCode(), http.StatusText(err.StatusCode()))
}

// StatusCode returns the HTTP status code for the given error.
func (err HTTPError) StatusCode() int {
	return int(err)
}

// HTTPStatusCode returns the HTTP status code corresponding to the given error.
//
// If the supplied error does not have a known status code we fallback to 500.
func HTTPStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var he HTTPError
	if errors.As(err, &he) {
		return he.StatusCode()
	}
	return http.StatusInternalServerError
}

// IsUserError reports whether or not the given error represents a mistake by the user.
func IsUserError(err error) bool {
	statusCode := HTTPStatusCode(err)
	return statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError
}

// CheckXSRF checks whether or not the given request includes XSRF headers if required.
func CheckXSRF(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		// XSRF headers are only required for requests that can have side effects...
		return nil
	}
	xsrfCookie, err := r.Cookie("_xsrf")
	if err != nil {
		return fmt.Errorf("%w: Missing the '_xsrf' cookie for a request", HTTPError(http.StatusForbidden))
	}
	if xsrfCookie == nil || xsrfCookie.Value == "" {
		return fmt.Errorf("%w: Missing the '_xsrf' cookie for a request", HTTPError(http.StatusForbidden))
	}
	xsrfHeader := r.Header.Get("X-XSRFToken")
	if xsrfHeader == "" {
		return fmt.Errorf("%w: Missing the 'X-XSRFToken' header for a request", HTTPError(http.StatusForbidden))
	}
	if xsrfHeader != xsrfCookie.Value {
		return HTTPError(http.StatusForbidden)
	}
	return nil
}

// requestID returns an ID used to uniquely identify the given request.
//
// The ID is stored in the request using the "X-Mixer-Request-ID" header.
//
// If that header is already present, then its value is reused. Otherwise,
// a random 64-bit ID is chosen and added to the request.
func requestID(r *http.Request) string {
	if requestID := r.Header.Get(requestIDHeader); requestID != "" {
		return requestID
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	requestID := fmt.Sprintf("%x", b)
	r.Header.Add(requestIDHeader, requestID)
	return requestID
}

// Log writes a log message using a consistent output format.
func Log(r *http.Request, msg any) {
	log.Printf("%s|%s|%s|%v\n", r.Method, r.URL.Path, requestID(r), msg)
}

// loggingResponseWriter wraps an http.ResponseWriter and logs the response status codes.
type loggingResponseWriter struct {
	r           *http.Request
	wrapped     http.ResponseWriter
	buff        *bytes.Buffer
	wroteHeader bool
}

// NewLoggingResponseWriter returns an http.ResponseWriter that wraps the given one and logs the response status.
func NewLoggingResponseWriter(w http.ResponseWriter, r *http.Request, responseBuffer *bytes.Buffer) http.ResponseWriter {
	return &loggingResponseWriter{wrapped: w, r: r, buff: responseBuffer}
}

// Write implements the http.Handler interface
func (lw *loggingResponseWriter) Write(bs []byte) (int, error) {
	if !lw.wroteHeader {
		lw.WriteHeader(http.StatusOK)
	}
	if lw.buff != nil {
		lw.buff.Write(bs)
	}
	return lw.wrapped.Write(bs)
}

// WriteHeader implements the http.Handler interface
func (lw *loggingResponseWriter) WriteHeader(code int) {
	if lw.wroteHeader {
		return
	}
	Log(lw.r, fmt.Sprintf("Response status: %s(%d)", http.StatusText(code), code))
	lw.wroteHeader = true
	lw.wrapped.WriteHeader(code)
}

// Header implements the http.Handler interface
func (lw *loggingResponseWriter) Header() http.Header {
	return lw.wrapped.Header()
}

// Hijack implements the http.Handler interface
func (lw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := lw.wrapped.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("wrapped writer %+v does not implement http.Hijacker", lw.wrapped)
	}
	return hj.Hijack()
}
