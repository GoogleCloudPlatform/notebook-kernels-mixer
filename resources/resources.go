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

// Package resources defines Golang representations for all of the resources defined by the Jupyter Swagger API.
package resources

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/GoogleCloudPlatform/notebook-kernels-mixer/util"
)

// KernelSpecs represents the collection of kernel specs returned by a kernel spec list call.
type KernelSpecs struct {
	Default     string                 `json:"default"`
	KernelSpecs map[string]*KernelSpec `json:"kernelspecs"`
	rawFields   map[string]any
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (ks *KernelSpecs) UnmarshalJSON(b []byte) error {
	rawFields := make(map[string]any)
	if err := json.Unmarshal(b, &rawFields); err != nil {
		return err
	}
	if len(rawFields) == 0 {
		// The JSON object was empty; leave the structured object empty too.
		return nil
	}
	if defaultVal, ok := rawFields["default"]; ok {
		defaultString, ok := defaultVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'default': %+v: %w", defaultVal, util.HTTPError(http.StatusBadRequest))
		}
		ks.Default = defaultString
	}
	specs, ok := rawFields["kernelspecs"]
	if !ok {
		ks.rawFields = rawFields
		return nil
	}
	ksMap, ok := specs.(map[string]any)
	if !ok {
		return fmt.Errorf("invalid value for the field 'kernelspecs': %+v: %w", specs, util.HTTPError(http.StatusBadRequest))
	}
	if len(ksMap) > 0 {
		ks.KernelSpecs = make(map[string]*KernelSpec)
		for name, specObj := range ksMap {
			specBytes, err := json.Marshal(specObj)
			if err != nil {
				return fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
			}
			var spec KernelSpec
			if err := json.Unmarshal(specBytes, &spec); err != nil {
				return fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
			}
			ks.KernelSpecs[name] = &spec
		}
	}
	ks.rawFields = rawFields
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (ks KernelSpecs) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]any)
	for k, v := range ks.rawFields {
		rawFields[k] = v
	}
	if len(ks.Default) > 0 {
		rawFields["default"] = ks.Default
	}
	if len(ks.KernelSpecs) > 0 {
		specMap := make(map[string]any)
		for name, spec := range ks.KernelSpecs {
			specBytes, err := json.Marshal(spec)
			if err != nil {
				return nil, fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
			}
			spec := make(map[string]any)
			if err := json.Unmarshal(specBytes, &spec); err != nil {
				return nil, fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
			}
			specMap[name] = spec
		}
		rawFields["kernelspecs"] = specMap
	}
	return json.Marshal(rawFields)
}

// Spec defines the `spec` field nested within a KernelSpec
type Spec struct {
	Language       string            `json:"language"`
	Argv           []string          `json:"argv"`
	DisplayName    string            `json:"display_name"`
	CodemirrorMode string            `json:"codemirror_mode,omitempty"`
	Env            map[string]string `json:"env"`
	HelpLinks      map[string]string `json:"help_links,omitempty"`
	Metadata       map[string]any    `json:"metadata"`
	InterruptMode  string            `json:"interrupt_mode,omitempty"`
}

// KernelSpec defines one of the available kernel configurations supported by a Jupyter server.
type KernelSpec struct {
	ID        string            `json:"name"`
	Spec      *Spec             `json:"spec"`
	Resources map[string]string `json:"resources"`
	rawFields map[string]any
}

// Identify returns the ID of the kernelspec.
func (ks *KernelSpec) Identify() string {
	return ks.ID
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (ks *KernelSpec) UnmarshalJSON(b []byte) error {
	rawFields := make(map[string]any)
	if err := json.Unmarshal(b, &rawFields); err != nil {
		return err
	}
	if len(rawFields) == 0 {
		// The JSON object was empty; leave the structured object empty too.
		return nil
	}
	if name, ok := rawFields["name"]; ok {
		idString, ok := name.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'name': %+v: %w", name, util.HTTPError(http.StatusBadRequest))
		}
		ks.ID = idString
	}
	if resources, ok := rawFields["resources"]; ok {
		resourcesMap, ok := resources.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid value for the field 'resources': %+v: %w", resources, util.HTTPError(http.StatusBadRequest))
		}
		ks.Resources = make(map[string]string)
		for name, val := range resourcesMap {
			if resource, ok := val.(string); ok {
				ks.Resources[name] = resource
			}
		}
	}
	spec, ok := rawFields["spec"]
	if !ok {
		ks.rawFields = rawFields
		return nil
	}
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
	}
	if err := json.Unmarshal(specBytes, &ks.Spec); err != nil {
		return fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
	}
	ks.rawFields = rawFields
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (ks KernelSpec) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]any)
	for k, v := range ks.rawFields {
		rawFields[k] = v
	}
	if len(ks.ID) > 0 {
		rawFields["name"] = ks.ID
	}
	if ks.Spec != nil {
		specBytes, err := json.Marshal(ks.Spec)
		if err != nil {
			return nil, fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
		}
		specMap := make(map[string]any)
		if err := json.Unmarshal(specBytes, &specMap); err != nil {
			return nil, fmt.Errorf("failure unmarshalling a nested `spec` field: %w", err)
		}
		for k, v := range specMap {
			if v == nil {
				delete(specMap, k)
			}
		}
		rawFields["spec"] = specMap
	}
	if len(ks.Resources) > 0 {
		rawFields["resources"] = ks.Resources
	}
	return json.Marshal(rawFields)
}

// Kernel defines a running process for executing code inside of a Jupyter server.
type Kernel struct {
	ID             string `json:"id,omitempty"`
	SpecID         string `json:"name"`
	LastActivity   string `json:"last_activity,omitempty"`
	Connections    int    `json:"connections"`
	ExecutionState string `json:"execution_state,omitempty"`

	// The `env` field is not part of the documented API, but is set by the notebook
	// server when calling into gateway servers. See here:
	//    https://github.com/jupyter/notebook/blob/2cfff07a39fa486a3f05c26b400fa26e1802a053/notebook/gateway/managers.py#L408
	Env       map[string]any `json:"env,omitempty"`
	rawFields map[string]any
}

// Identify returns the ID of the kernel.
func (k *Kernel) Identify() string {
	return k.ID
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (k *Kernel) UnmarshalJSON(b []byte) error {
	rawFields := make(map[string]any)
	if err := json.Unmarshal(b, &rawFields); err != nil {
		return err
	}
	if len(rawFields) == 0 {
		// The JSON object was empty; leave the structured object empty too.
		return nil
	}
	if idVal, ok := rawFields["id"]; ok {
		idString, ok := idVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'id': %+v: %w", idVal, util.HTTPError(http.StatusBadRequest))
		}
		k.ID = idString
	}
	if specIDVal, ok := rawFields["name"]; ok {
		specIDString, ok := specIDVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'name': %+v: %w", specIDVal, util.HTTPError(http.StatusBadRequest))
		}
		k.SpecID = specIDString
	}
	if lastActivityVal, ok := rawFields["last_activity"]; ok {
		lastActivityString, ok := lastActivityVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'last_activity': %+v: %w", lastActivityVal, util.HTTPError(http.StatusBadRequest))
		}
		k.LastActivity = lastActivityString
	}
	if connectionsVal, ok := rawFields["connections"]; ok {
		connectionsNumber, ok := connectionsVal.(float64)
		if !ok {
			return fmt.Errorf("invalid type for the field 'connections': %+v: %w", connectionsVal, util.HTTPError(http.StatusBadRequest))
		}
		k.Connections = int(connectionsNumber)
	}
	if executionStateVal, ok := rawFields["execution_state"]; ok {
		executionStateString, ok := executionStateVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'execution_state': %+v: %w", executionStateVal, util.HTTPError(http.StatusBadRequest))
		}
		k.ExecutionState = executionStateString
	}
	if envVal, ok := rawFields["env"]; ok {
		envMap, ok := envVal.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid value for the field 'env': %+v: %w", envVal, util.HTTPError(http.StatusBadRequest))
		}
		k.Env = envMap
	}
	k.rawFields = rawFields
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (k Kernel) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]any)
	for key, v := range k.rawFields {
		rawFields[key] = v
	}
	if len(k.ID) > 0 {
		rawFields["id"] = k.ID
	}
	if len(k.SpecID) > 0 {
		rawFields["name"] = k.SpecID
	}
	if len(k.LastActivity) > 0 {
		rawFields["last_activity"] = k.LastActivity
	}
	// Unconditionally set the "connections" field because Jupyter requires it to be present.
	rawFields["connections"] = k.Connections
	if len(k.ExecutionState) > 0 {
		rawFields["execution_state"] = k.ExecutionState
	}
	if len(k.Env) > 0 {
		rawFields["env"] = k.Env
	}
	return json.Marshal(rawFields)
}

// Session defines a mapping between a file path and a kernel.
type Session struct {
	ID        string            `json:"id"`
	Path      string            `json:"path"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Kernel    *Kernel           `json:"kernel"`
	Notebook  map[string]string `json:"notebook,omitempty"`
	rawFields map[string]any
}

// Identify returns the ID of the kernel.
func (s *Session) Identify() string {
	return s.ID
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (s *Session) UnmarshalJSON(b []byte) error {
	rawFields := make(map[string]any)
	if err := json.Unmarshal(b, &rawFields); err != nil {
		return err
	}
	if len(rawFields) == 0 {
		// The JSON object was empty; leave the structured object empty too.
		return nil
	}
	if idVal, ok := rawFields["id"]; ok {
		idString, ok := idVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'id': %+v: %w", idVal, util.HTTPError(http.StatusBadRequest))
		}
		s.ID = idString
	}
	if pathVal, ok := rawFields["path"]; ok {
		pathString, ok := pathVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'path': %+v: %w", pathVal, util.HTTPError(http.StatusBadRequest))
		}
		s.Path = pathString
	}
	if nameVal, ok := rawFields["name"]; ok {
		nameString, ok := nameVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'name': %+v: %w", nameVal, util.HTTPError(http.StatusBadRequest))
		}
		s.Name = nameString
	}
	if typeVal, ok := rawFields["type"]; ok {
		typeString, ok := typeVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'type': %+v: %w", typeVal, util.HTTPError(http.StatusBadRequest))
		}
		s.Type = typeString
	}
	if notebookVal, ok := rawFields["notebook"]; ok {
		notebookMap, ok := notebookVal.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid value for the field 'notebook': %+v: %w", notebookVal, util.HTTPError(http.StatusBadRequest))
		}
		s.Notebook = make(map[string]string)
		for name, val := range notebookMap {
			if valStr, ok := val.(string); ok {
				s.Notebook[name] = valStr
			}
		}
	}
	k, ok := rawFields["kernel"]
	if !ok {
		return nil
	}
	kernelBytes, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("failure unmarshalling a nested `kernel` field: %w", err)
	}
	if err := json.Unmarshal(kernelBytes, &s.Kernel); err != nil {
		return fmt.Errorf("failure unmarshalling a nested `kernel` field: %w", err)
	}
	s.rawFields = rawFields
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (s Session) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]any)
	for k, v := range s.rawFields {
		rawFields[k] = v
	}
	if len(s.ID) > 0 {
		rawFields["id"] = s.ID
	}
	if len(s.Path) > 0 {
		rawFields["path"] = s.Path
	}
	if len(s.Name) > 0 {
		rawFields["name"] = s.Name
	}
	if len(s.Type) > 0 {
		rawFields["type"] = s.Type
	}
	if len(s.Notebook) > 0 {
		rawFields["notebook"] = s.Notebook
	}
	if s.Kernel == nil {
		return json.Marshal(rawFields)
	}
	kernelBytes, err := json.Marshal(s.Kernel)
	if err != nil {
		return nil, fmt.Errorf("failure unmarshalling a nested `kernel` field: %w", err)
	}
	kernelMap := make(map[string]any)
	if err := json.Unmarshal(kernelBytes, &kernelMap); err != nil {
		return nil, fmt.Errorf("failure unmarshalling a nested `kernel` field: %w", err)
	}
	for k, v := range kernelMap {
		if v == nil {
			delete(kernelMap, k)
		}
	}
	rawFields["kernel"] = kernelMap
	return json.Marshal(rawFields)
}

// Terminal defines an interactive terminal running inside of a Jupyter server.
type Terminal struct {
	ID        string `json:"name"`
	rawFields map[string]any
}

// Identify returns the ID of the kernel.
func (t *Terminal) Identify() string {
	return t.ID
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (t *Terminal) UnmarshalJSON(b []byte) error {
	rawFields := make(map[string]any)
	if err := json.Unmarshal(b, &rawFields); err != nil {
		return err
	}
	if len(rawFields) == 0 {
		// The JSON object was empty; leave the structured object empty too.
		return nil
	}
	if idVal, ok := rawFields["name"]; ok {
		idString, ok := idVal.(string)
		if !ok {
			return fmt.Errorf("invalid value for the field 'name': %+v: %w", idVal, util.HTTPError(http.StatusBadRequest))
		}
		t.ID = idString
	}
	t.rawFields = rawFields
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (t Terminal) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]any)
	for k, v := range t.rawFields {
		rawFields[k] = v
	}
	if len(t.ID) > 0 {
		rawFields["name"] = t.ID
	}
	return json.Marshal(rawFields)
}
