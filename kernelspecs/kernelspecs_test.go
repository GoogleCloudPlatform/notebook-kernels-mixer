package kernelspecs

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google3/third_party/notebookkernelsmixer/backends/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
)

func TestCombinedKernelSpecs(t *testing.T) {
	testCases := []struct {
		desc                      string
		localBackendResponseCode  int
		localBackendResponse      *resources.KernelSpecs
		remoteBackendResponseCode int
		remoteBackendResponse     *resources.KernelSpecs
		wantErr                   error
	}{
		{
			desc:                     "Bad local backend",
			localBackendResponseCode: 502,
			localBackendResponse:     &resources.KernelSpecs{},
			wantErr:                  cmpopts.AnyError,
		},
		{
			desc:                      "Bad remote backend",
			localBackendResponseCode:  200,
			localBackendResponse:      &resources.KernelSpecs{},
			remoteBackendResponseCode: 502,
			remoteBackendResponse:     &resources.KernelSpecs{},
			wantErr:                   cmpopts.AnyError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			localRespBytes, err := json.Marshal(tc.localBackendResponse)
			if err != nil {
				t.Fatalf("json.Marshal(%v) got error %v want nil", tc.localBackendResponse, err)
			}
			remoteRespBytes, err := json.Marshal(tc.remoteBackendResponse)
			if err != nil {
				t.Fatalf("json.Marshal(%v) got error %v want nil", tc.remoteBackendResponse, err)
			}

			localBackend := backends.New("local backend", "local suffix", "local host", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.localBackendResponseCode)
				w.Write(localRespBytes)
			}))
			remoteBackend := backends.New("remote backend", "remote suffix", "remote host", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.remoteBackendResponseCode)
				w.Write(remoteRespBytes)
			}))

			_, err = CombinedKernelSpecs(localBackend, remoteBackend)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("CombinedKernelSpecs(%v, %v) got error %v want %v", localBackend, localBackend, err, tc.wantErr)
			}
		})
	}
}
