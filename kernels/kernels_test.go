package kernels

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
)

func TestCombinedKernels(t *testing.T) {
	testCases := []struct {
		desc                      string
		localBackendResponseCode  int
		localBackendResponse      []*resources.Kernel
		remoteBackendResponseCode int
		remoteBackendResponse     []*resources.Kernel
		want                      []*resources.Kernel
		wantErr                   error
	}{
		{
			desc:                     "Bad local backend",
			localBackendResponseCode: 502,
			localBackendResponse:     []*resources.Kernel{},
			want:                     []*resources.Kernel{},
			wantErr:                  cmpopts.AnyError,
		},
		{
			desc:                      "Healthy local backend, Bad Remote backend basic",
			localBackendResponseCode:  200,
			localBackendResponse:      []*resources.Kernel{},
			remoteBackendResponseCode: 502,
			remoteBackendResponse:     []*resources.Kernel{},
			want:                      []*resources.Kernel{},
		},
		{
			desc:                      "Healthy local+remote backend basic",
			localBackendResponseCode:  200,
			localBackendResponse:      []*resources.Kernel{},
			remoteBackendResponseCode: 200,
			remoteBackendResponse:     []*resources.Kernel{},
			want:                      []*resources.Kernel{},
		},
		{
			desc:                     "Healthy local backend, Bad remote backend",
			localBackendResponseCode: 200,
			localBackendResponse: []*resources.Kernel{
				&resources.Kernel{
					ID:             "02587c70-e1df-40a5-80f8-76534374817a",
					Connections:    1,
					LastActivity:   "2023-02-14T02:50:02.922555Z",
					ExecutionState: "idle",
					SpecID:         "id",
				},
			},
			remoteBackendResponseCode: 502,
			remoteBackendResponse:     []*resources.Kernel{},
			want: []*resources.Kernel{
				&resources.Kernel{
					ID:             "02587c70-e1df-40a5-80f8-76534374817a",
					Connections:    1,
					LastActivity:   "2023-02-14T02:50:02.922555Z",
					ExecutionState: "idle",
					SpecID:         "local-id",
				},
			},
		},
		{
			desc:                     "Healthy local+remote backend",
			localBackendResponseCode: 200,
			localBackendResponse: []*resources.Kernel{
				&resources.Kernel{
					ID:             "local-deadbeef",
					Connections:    1,
					LastActivity:   "2023-02-14T02:50:02.922555Z",
					ExecutionState: "idle",
					SpecID:         "id1",
				},
			},
			remoteBackendResponseCode: 200,
			remoteBackendResponse: []*resources.Kernel{
				&resources.Kernel{
					ID:             "remote-deadbeef",
					Connections:    1,
					LastActivity:   "2023-02-13T02:50:02.922555Z",
					ExecutionState: "busy",
					SpecID:         "id2",
				},
			},
			want: []*resources.Kernel{
				&resources.Kernel{
					ID:             "local-deadbeef",
					Connections:    1,
					LastActivity:   "2023-02-14T02:50:02.922555Z",
					ExecutionState: "idle",
					SpecID:         "local-id1",
				},
				&resources.Kernel{
					ID:             "remote-deadbeef",
					Connections:    1,
					LastActivity:   "2023-02-13T02:50:02.922555Z",
					ExecutionState: "busy",
					SpecID:         "remote-id2",
				},
			},
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

			localBackend := backends.New("local", " (Local)", "local host", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.localBackendResponseCode)
				w.Write(localRespBytes)
			}))
			remoteBackend := backends.New("remote", " (Remote)", "remote host", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.remoteBackendResponseCode)
				w.Write(remoteRespBytes)
			}))
			kR := &kernelsRecords{kernelsToBackendsMap: map[string]*backends.Backend{
				"local": localBackend, "remote": remoteBackend}}
			got, err := kR.combined(localBackend, remoteBackend)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("combined(%v, %v) got error %v want %v", localBackend, remoteBackend, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(got, tc.want, cmp.AllowUnexported(resources.Kernel{})); diff != "" {
				t.Errorf("combined() returned unexpected diff (-want +got):\n%s", diff)
			}
		})

	}
}
