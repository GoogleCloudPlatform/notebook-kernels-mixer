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

// Command mixer is a reverse proxy that enables switching between kernels running locally or remotely.
//
// Prerequisites:
//
//	You must have Jupyter Lab installed on your workstation (i.e. the command `jupyter lab` should work).
//
// Example usage:
//
//	export JUPYTER_PORT=8082
//	export JUPYTER_TOKEN="$(uuidgen)"
//	jupyter lab --no-browser --port-retries=0 --port="${JUPYTER_PORT}" --notebook-dir="${HOME}" --NotebookApp.token="${JUPYTER_TOKEN}" --debug &
//	mixer \
//	  --mixer-project="${PROJECT}" \
//	  --mixer-region="${REGION}" \
//	  --jupyter-port="${JUPYTER_PORT}" \
//	  --jupyter-token="${JUPYTER_TOKEN}"
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/oauth2"
	"google3/third_party/notebookkernelsmixer/backends/backends"
	"google3/third_party/notebookkernelsmixer/kernels/kernels"
	"google3/third_party/notebookkernelsmixer/kernelspecs/kernelspecs"
	"google3/third_party/notebookkernelsmixer/sessions/sessions"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

var (
	mixerProject = flag.String("mixer-project", "", "The GCP project to use.")
	mixerRegion  = flag.String("mixer-region", "", "The GCP region to use.")
	mixerHost    = flag.String("mixer-host", "kernels.googleusercontent.com", "The parent hostname for the kernels mixer.")
	remoteURL    = flag.String("remote-url", "", "The full URL for the remote backend. If unset, this is constructed based on the --mixer-host")

	jupyterPort  = flag.Int("jupyter-port", 8082, "The port on which the locally running Jupyter server is listening.")
	jupyterToken = flag.String("jupyter-token", "", "The token used to authenticate calls to the locally running Jupyter instance.")
	port         = flag.Int("port", 8081, "Port on which to start the server.")

	externalHostname = flag.String("external-hostname", "", "The hostname users will actually connect to to use this client.")

	gceMetadataOverrideIP = flag.String("gce-metadata-override-ip", "", "Override GCE metadata IP when querying credentials.")

	contextRequestTimeout = flag.Duration("context_request_timeout", 10*time.Second, "How long to give HTTP requests to complete. For outgoing client request, the context controls the entire lifetime of a request and its response: obtaining a connection, sending the request, and reading the response headers and body.")

	logRequestHeaders      = flag.Bool("log-all-request-headers", false, "Whether or not to log the headers for every request.")
	logAllRequestResponses = flag.Bool("log-all-request-responses", false, "Whether or not to log the response code for every request.")
	logAllResponseBodies   = flag.Bool("log-all-response-bodies", false, "Whether or not to log the full response body for every request. Does nothing unless --log-all-request-responses is enabled.")
)

// configHelperResp corresponds to the JSON output of the `gcloud config-helper` command.
type configHelperResp struct {
	Credential struct {
		AccessToken string `json:"access_token"`
		TokenExpiry string `json:"token_expiry"`
	} `json:"credential"`
}

func gcloudToken() (*oauth2.Token, error) {
	cmd := exec.Command("gcloud", "config", "config-helper", "--format=json")
	cmd.Env = os.Environ()
	if *gceMetadataOverrideIP != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("GCE_METADATA_HOST=%s", *gceMetadataOverrideIP),
			fmt.Sprintf("GCE_METADATA_ROOT=%s", *gceMetadataOverrideIP),
			fmt.Sprintf("GCE_METADATA_IP=%s", *gceMetadataOverrideIP),
		)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running the config-helper command: %w", err)
	}
	var r configHelperResp
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("parsing the config-helper output: %w", err)
	}
	return &oauth2.Token{
		AccessToken: r.Credential.AccessToken,
		// Force refresh token every 10 seconds.
		//
		// This reduces the latency in picking up changes a user makes to their credentials
		// after the mixer startsup.
		Expiry: time.Now().Add(10 * time.Second),
	}, nil
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (tsf tokenSourceFunc) Token() (*oauth2.Token, error) {
	return tsf()
}

func clearExternalOriginForWebsocketRequests(r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		return
	}

	// The mixer does not allow cross origin websocket requests, so we clear out the
	// origin header if it is set to something we allow.
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		util.Log(r, fmt.Sprintf("Malformed URL in origin header: %q", origin))
		return
	}
	if originURL.Host == *externalHostname {
		r.Header.Del("Origin")
	}
}

const (
	localBackendName        = "local"
	localResourceNameSuffix = " (Local)"

	remoteBackendName        = "remote"
	remoteResourceNameSuffix = " (Remote)"
)

func main() {
	flag.Parse()
	var mixerURL *url.URL
	var err error
	if *remoteURL == "" {
		if *mixerProject == "" || *mixerRegion == "" {
			log.Fatal("You must specify the project and region of the kernels mixer")
		}
		mixerURL, err = url.Parse(fmt.Sprintf("https://%s-dot-%s.%s", *mixerProject, *mixerRegion, *mixerHost))
	} else {
		mixerURL, err = url.Parse(*remoteURL)
	}
	if err != nil {
		log.Fatalf("Failure parsing the URL for the kernel mixer: %v", err)
	}

	mixerProxy := httputil.NewSingleHostReverseProxy(mixerURL)
	baseDirector := mixerProxy.Director
	mixerProxy.Director = func(r *http.Request) {
		baseDirector(r)
		if errs := util.ModifyProxiedRequestForHost(r, mixerURL.Host); len(errs) > 0 {
			util.Log(r, fmt.Sprintf("Unexpected errors modifying proxied request headers: %v\n", errs))
		}
		clearExternalOriginForWebsocketRequests(r)
	}
	mixerProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		util.Log(r, fmt.Sprintf("Error forwarding a request to the kernels mixer: %v", err))
		if websocket.IsWebSocketUpgrade(r) {
			// Do not report the error via the response status code, as if we do then JupyterLab will
			// not retry the websocket connection and will unnecessarily report the kernel as disconnected.
			return
		}
		// Report the proxy error using the same status as the default error handler.
		w.WriteHeader(http.StatusBadGateway)
	}

	tokenSource := oauth2.ReuseTokenSource(nil, tokenSourceFunc(gcloudToken))
	// Do the initial token fetch at startup.
	tokenSource.Token()
	wrappedSessionsProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := tokenSource.Token()
		if err != nil {
			msg := fmt.Sprintf("failure generating the authorization header: %v", err)
			util.Log(r, msg)
			http.Error(w, msg, util.HTTPStatusCode(err))
			return
		}
		r.Header.Del("Authorization")
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
		mixerProxy.ServeHTTP(w, r)
	})
	remoteBackend := backends.New(remoteBackendName, remoteResourceNameSuffix, mixerURL.Host, wrappedSessionsProxy)

	localBackendHost := fmt.Sprintf("localhost:%d", *jupyterPort)
	localURL, err := url.Parse("http://" + localBackendHost)
	if err != nil {
		log.Fatalf("Failure parsing the URL for the locally-running Jupyter Lab instance: %v", err)
	}
	localProxy := httputil.NewSingleHostReverseProxy(localURL)
	localProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		util.Log(r, fmt.Sprintf("Error forwarding a request to the local Jupyter server. Verify %s is active. %v", localURL.String(), err))
		if websocket.IsWebSocketUpgrade(r) {
			// Do not report the error via the response status code, as if we do then JupyterLab will
			// not retry the websocket connection and will unnecessarily report the kernel as disconnected.
			return
		}
		// Report the proxy error using the same status as the default error handler.
		w.WriteHeader(http.StatusBadGateway)
	}
	if len(*jupyterToken) > 0 {
		localProxyBaseDirector := localProxy.Director
		localProxy.Director = func(r *http.Request) {
			localProxyBaseDirector(r)
			q := r.URL.Query()
			q.Set("token", *jupyterToken)
			r.URL.RawQuery = q.Encode()
		}
	}
	localBackend := backends.New(localBackendName, localResourceNameSuffix, localBackendHost, localProxy)

	kernelSpecsHandler := kernelspecs.Handler(localBackend, remoteBackend)
	kernelsHandler := kernels.Handler(localBackend, remoteBackend)
	sessionsHandler := sessions.Handler(localBackend, remoteBackend)

	mux := http.NewServeMux()
	mux.Handle("/api/kernelspecs", kernelSpecsHandler)
	mux.Handle("/api/kernelspecs/", kernelSpecsHandler)
	mux.Handle("/kernelspecs/", kernelSpecsHandler)

	mux.Handle("/api/kernels", kernelsHandler)
	mux.Handle("/api/kernels/", kernelsHandler)

	mux.Handle("/api/sessions", sessionsHandler)
	mux.Handle("/api/sessions/", sessionsHandler)
	mux.Handle("/", localProxy)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *logRequestHeaders {
			util.Log(r, fmt.Sprintf("Request headers: %+v", r.Header))
		}
		if *logAllRequestResponses {
			var buff *bytes.Buffer
			if *logAllResponseBodies {
				var responseBuff bytes.Buffer
				buff = &responseBuff
				defer func() {
					go func(respBuff *bytes.Buffer) {
						util.Log(r, fmt.Sprintf("Response body: %q", respBuff.String()))
					}(buff)
				}()
			}
			w = util.NewLoggingResponseWriter(w, r, buff)
		}
		if len(*jupyterToken) > 0 {
			if token := r.Header.Get("token"); token != *jupyterToken {
				util.Log(r, fmt.Sprintf("Token mismatch: %q", token))
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		if err := util.CheckXSRF(r); err != nil {
			util.Log(r, fmt.Sprintf("XSRF error: %v", err))
			http.Error(w, err.Error(), util.HTTPStatusCode(err))
			return
		}
		if !websocket.IsWebSocketUpgrade(r) {
			ctx, cancel := context.WithTimeout(r.Context(), *contextRequestTimeout)
			defer cancel()
			r = r.WithContext(ctx)
		}
		mux.ServeHTTP(w, r)
	})
	localAddress := fmt.Sprintf("[::1]:%d", *port)
	log.Printf("Listening on %q...\n", localAddress)
	log.Fatal(http.ListenAndServe(localAddress, nil))
}
