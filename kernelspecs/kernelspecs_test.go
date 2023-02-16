package kernelspecs

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/backends"
	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/resources"
)

func TestCombinedKernelSpecs(t *testing.T) {
	testCases := []struct {
		desc                      string
		localBackendResponseCode  int
		localBackendResponse      *resources.KernelSpecs
		remoteBackendResponseCode int
		remoteBackendResponse     *resources.KernelSpecs
		want                      *resources.KernelSpecs
		wantErr                   error
	}{
		{
			desc:                     "Bad local backend",
			localBackendResponseCode: 502,
			localBackendResponse:     &resources.KernelSpecs{},
			want:                     &resources.KernelSpecs{},
			wantErr:                  cmpopts.AnyError,
		},
		{
			desc:                     "Healthy local backend, Bad remote backend",
			localBackendResponseCode: 200,
			localBackendResponse: &resources.KernelSpecs{
				Default: "base",
				KernelSpecs: map[string]*resources.KernelSpec{
					"default": &resources.KernelSpec{
						ID: "base",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"},
							DisplayName: "Python 3",
						},
						Resources: map[string]string{
							"logo-64x64": "/kernelspecs/base/logo-64x64.png",
							"logo-svg":   "/kernelspecs/base/logo-svg.svg",
							"logo-32x32": "/kernelspecs/base/logo-32x32.png",
						},
					},
				},
			},
			want: &resources.KernelSpecs{
				Default: "local-base",
				KernelSpecs: map[string]*resources.KernelSpec{
					"local-default": &resources.KernelSpec{
						ID: "local-base",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"},
							DisplayName: "Python 3 (Local)",
						},
						Resources: map[string]string{
							"logo-64x64": "/kernelspecs/local-base/logo-64x64.png",
							"logo-svg":   "/kernelspecs/local-base/logo-svg.svg",
							"logo-32x32": "/kernelspecs/local-base/logo-32x32.png",
						},
					},
				},
			},
			remoteBackendResponseCode: 502,
			remoteBackendResponse:     &resources.KernelSpecs{},
		},
		{
			desc:                     "Healthy local and remote backends",
			localBackendResponseCode: 200,
			localBackendResponse: &resources.KernelSpecs{
				Default: "base",
				KernelSpecs: map[string]*resources.KernelSpec{
					"base": &resources.KernelSpec{
						ID: "base",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"},
							DisplayName: "Python 3",
						},
						Resources: map[string]string{
							"logo-64x64": "/kernelspecs/base/logo-64x64.png",
							"logo-svg":   "/kernelspecs/base/logo-svg.svg",
							"logo-32x32": "/kernelspecs/base/logo-32x32.png",
						},
					},
				},
			},
			remoteBackendResponseCode: 200,
			remoteBackendResponse: &resources.KernelSpecs{
				Default: "pyspark",
				KernelSpecs: map[string]*resources.KernelSpec{
					"pyspark": &resources.KernelSpec{
						ID: "pyspark",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"bash", "-c", "PYSPARK_DRIVER_PYTHON_OPTS='kernel -f {connection_file}' pyspark"},
							DisplayName: "PySpark",
							Env: map[string]string{
								"PYSPARK_DRIVER_PYTHON": "/opt/conda/miniconda3/bin/ipython",
								"PYSPARK_PYTHON":        "/opt/conda/miniconda3/bin/python"},
						},
						Resources: map[string]string{
							"endpointParentResource": "//dataproc.googleapis.com/projects/p1/regions/us-west1/clusters/dataproc-us-west1",
						},
					},
				},
			},
			want: &resources.KernelSpecs{
				Default: "remote-pyspark",
				KernelSpecs: map[string]*resources.KernelSpec{
					"local-base": &resources.KernelSpec{
						ID: "local-base",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"},
							DisplayName: "Python 3 (Local)",
						},
						Resources: map[string]string{
							"logo-64x64": "/kernelspecs/local-base/logo-64x64.png",
							"logo-svg":   "/kernelspecs/local-base/logo-svg.svg",
							"logo-32x32": "/kernelspecs/local-base/logo-32x32.png",
						},
					},
					"remote-pyspark": &resources.KernelSpec{
						ID: "remote-pyspark",
						Spec: &resources.Spec{
							Language:    "python",
							Argv:        []string{"bash", "-c", "PYSPARK_DRIVER_PYTHON_OPTS='kernel -f {connection_file}' pyspark"},
							DisplayName: "PySpark (Remote)",
							Env: map[string]string{
								"PYSPARK_DRIVER_PYTHON": "/opt/conda/miniconda3/bin/ipython",
								"PYSPARK_PYTHON":        "/opt/conda/miniconda3/bin/python"},
						},
						Resources: map[string]string{
							"endpointParentResource": "//dataproc.googleapis.com/projects/p1/regions/us-west1/clusters/dataproc-us-west1",
						},
					},
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

			got, err := CombinedKernelSpecs(localBackend, remoteBackend)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("CombinedKernelSpecs(%v, %v) got error %v want %v", localBackend, remoteBackend, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(got, tc.want, cmp.AllowUnexported(resources.KernelSpecs{}, resources.KernelSpec{})); diff != "" {
				t.Errorf("CombinedKernelSpecs() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
