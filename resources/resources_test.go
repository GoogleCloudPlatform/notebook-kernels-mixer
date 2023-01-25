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
package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestUnmarshalAndMarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		Description string
		Source      string
		Got         any
		Want        any
	}{
		{
			Description: "Empty KernelSpecs",
			Source:      "{}",
			Got:         &KernelSpecs{},
			Want:        &KernelSpecs{},
		},
		{
			Description: "Empty KernelSpecs with raw fields",
			Source:      "{\"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &KernelSpecs{},
			Want: &KernelSpecs{
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Simple KernelSpecs",
			Source:      "{\"default\": \"default\", \"kernelspecs\": {\"default\": {\"name\": \"default\"}}}",
			Got:         &KernelSpecs{},
			Want: &KernelSpecs{
				Default: "default",
				KernelSpecs: map[string]*KernelSpec{
					"default": &KernelSpec{
						ID: "default",
					},
				},
			},
		},
		{
			Description: "Simple KernelSpecs with raw fields",
			Source:      "{\"default\": \"default\", \"kernelspecs\": {\"default\": {\"name\": \"default\"}}, \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &KernelSpecs{},
			Want: &KernelSpecs{
				Default: "default",
				KernelSpecs: map[string]*KernelSpec{
					"default": &KernelSpec{
						ID: "default",
					},
				},
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Empty KernelSpec",
			Source:      "{}",
			Got:         &KernelSpec{},
			Want:        &KernelSpec{},
		},
		{
			Description: "Empty KernelSpec with raw fields",
			Source:      "{\"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &KernelSpec{},
			Want: &KernelSpec{
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Simple KernelSpec",
			Source:      "{\"name\": \"id\", \"spec\": {\"language\": \"python\", \"argv\": [\"--some\", \"--flags\"], \"display_name\": \"Python 3\"}, \"resources\": {\"a\": \"b\", \"c\": \"d\"}}",
			Got:         &KernelSpec{},
			Want: &KernelSpec{
				ID: "id",
				Spec: &Spec{
					Language:    "python",
					Argv:        []string{"--some", "--flags"},
					DisplayName: "Python 3",
				},
				Resources: map[string]string{
					"a": "b",
					"c": "d",
				},
			},
		},
		{
			Description: "Simple KernelSpec with raw fields",
			Source:      "{\"name\": \"id\", \"spec\": {\"language\": \"python\", \"argv\": [\"--some\", \"--flags\"], \"display_name\": \"Python 3\"}, \"resources\": {\"a\": \"b\", \"c\": \"d\"}, \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &KernelSpec{},
			Want: &KernelSpec{
				ID: "id",
				Spec: &Spec{
					Language:    "python",
					Argv:        []string{"--some", "--flags"},
					DisplayName: "Python 3",
				},
				Resources: map[string]string{
					"a": "b",
					"c": "d",
				},
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Empty Kernel",
			Source:      "{\"connections\": 0}",
			Got:         &Kernel{},
			Want:        &Kernel{},
		},
		{
			Description: "Empty Kernel with raw fields",
			Source:      "{\"connections\": 0, \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &Kernel{},
			Want: &Kernel{
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Simple Kernel",
			Source:      "{\"id\": \"ID\", \"name\": \"specID\", \"last_activity\": \"some time ago\", \"connections\": 5, \"execution_state\": \"being tested\", \"env\": {\"env-var\": 1}}",
			Got:         &Kernel{},
			Want: &Kernel{
				ID:             "ID",
				SpecID:         "specID",
				LastActivity:   "some time ago",
				Connections:    5,
				ExecutionState: "being tested",
				// N.B. `float64(1)` instead of just `1`, because JSON numbers are floating point.
				Env: map[string]any{"env-var": float64(1)},
			},
		},
		{
			Description: "Simple Kernel with raw fields",
			Source:      "{\"id\": \"ID\", \"name\": \"specID\", \"last_activity\": \"some time ago\", \"connections\": 5, \"execution_state\": \"being tested\", \"env\": {\"env-var\": 1}, \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &Kernel{},
			Want: &Kernel{
				ID:             "ID",
				SpecID:         "specID",
				LastActivity:   "some time ago",
				Connections:    5,
				ExecutionState: "being tested",
				// N.B. `float64(1)` instead of just `1`, because JSON numbers are floating point.
				Env: map[string]any{"env-var": float64(1)},
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Session with kernel with raw fields",
			Source:      "{\"id\": \"sessionID\", \"name\": \"sessionName\", \"path\": \"/path/\", \"type\": \"sessionType\", \"kernel\": {\"id\": \"kernelID\", \"name\": \"specID\", \"last_activity\": \"some time ago\", \"connections\": 5, \"execution_state\": \"being tested\", \"foo\": \"bar\", \"baz\": \"bat\"}, \"notebook\": {\"a\": \"b\"}}",
			Got:         &Session{},
			Want: &Session{
				ID:   "sessionID",
				Name: "sessionName",
				Path: "/path/",
				Type: "sessionType",
				Kernel: &Kernel{
					ID:             "kernelID",
					SpecID:         "specID",
					LastActivity:   "some time ago",
					Connections:    5,
					ExecutionState: "being tested",
					rawFields: map[string]any{
						"foo": "bar",
						"baz": "bat",
					},
				},
				Notebook: map[string]string{
					"a": "b",
				},
			},
		},
		{
			Description: "Session with raw fields",
			Source:      "{\"id\": \"sessionID\", \"name\": \"sessionName\", \"path\": \"/path/\", \"type\": \"sessionType\", \"kernel\": {\"id\": \"kernelID\", \"name\": \"specID\", \"last_activity\": \"some time ago\", \"connections\": 5, \"execution_state\": \"being tested\"}, \"notebook\": {\"a\": \"b\"}, \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &Session{},
			Want: &Session{
				ID:   "sessionID",
				Name: "sessionName",
				Path: "/path/",
				Type: "sessionType",
				Kernel: &Kernel{
					ID:             "kernelID",
					SpecID:         "specID",
					LastActivity:   "some time ago",
					Connections:    5,
					ExecutionState: "being tested",
				},
				Notebook: map[string]string{
					"a": "b",
				},
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Empty Terminal",
			Source:      "{}",
			Got:         &Terminal{},
			Want:        &Terminal{},
		},
		{
			Description: "Empty Terminal with raw fields",
			Source:      "{\"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &Terminal{},
			Want: &Terminal{
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
		{
			Description: "Simple Terminal",
			Source:      "{\"name\": \"Name\"}",
			Got:         &Terminal{},
			Want: &Terminal{
				ID: "Name",
			},
		},
		{
			Description: "Simple Terminal with raw fields",
			Source:      "{\"name\": \"Name\", \"foo\": \"bar\", \"baz\": \"bat\"}",
			Got:         &Terminal{},
			Want: &Terminal{
				ID: "Name",
				rawFields: map[string]any{
					"foo": "bar",
					"baz": "bat",
				},
			},
		},
	}
	for _, testCase := range testCases {
		if err := json.Unmarshal([]byte(testCase.Source), testCase.Got); err != nil {
			t.Errorf("Failure unmarshalling the resource for %q: %v", testCase.Description, err)
		} else if diff := cmp.Diff(testCase.Got, testCase.Want, cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported(KernelSpecs{}, KernelSpec{}, Kernel{}, Session{}, Terminal{})); len(diff) > 0 {
			t.Errorf("Unexpected diff when unmarshalling the source for %q:\n\t %v", testCase.Description, diff)
		} else if output, err := json.Marshal(testCase.Got); err != nil {
			t.Errorf("Failure marshalling the unmarshalled resource for %q: %v", testCase.Description, err)
		} else {
			sourceRawFields := make(map[string]any)
			outputRawFields := make(map[string]any)
			if err := json.Unmarshal([]byte(testCase.Source), &sourceRawFields); err != nil {
				t.Errorf("Failure unmarshalling the resource for %q as raw fields: %v", testCase.Description, err)
			} else if err := json.Unmarshal(output, &outputRawFields); err != nil {
				t.Errorf("Failure unmarshalling the result for %q as raw fields: %v", testCase.Description, err)
			} else if rawFieldsDiff := cmp.Diff(outputRawFields, sourceRawFields, cmpopts.EquateEmpty(), cmpopts.SortMaps(func(a, b string) bool { return a < b })); len(rawFieldsDiff) > 0 {
				t.Logf("Output raw: %v", string(output))
				t.Errorf("Unexpected raw fields diff for the marshalled value for %q:\n\t %v", testCase.Description, rawFieldsDiff)
			}
		}
	}
}
