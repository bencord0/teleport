/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"fmt"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/utils"
)

// UserGroup specifies an externally sourced group.
type UserGroup interface {
	ResourceWithLabels
}

// NewUserGroup returns a new UserGroup.
func NewUserGroup(metadata Metadata) (UserGroup, error) {
	g := &UserGroupV1{
		ResourceHeader: ResourceHeader{
			Metadata: metadata,
		},
	}
	if err := g.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return g, nil
}

// String returns the user group string representation.
func (g *UserGroupV1) String() string {
	return fmt.Sprintf("UserGroupV1(Name=%v, Labels=%v)",
		g.GetName(), g.GetAllLabels())
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (g *UserGroupV1) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(g.GetAllLabels()), g.GetName())
	return MatchSearch(fieldVals, values, nil)
}

// setStaticFields sets static resource header and metadata fields.
func (g *UserGroupV1) setStaticFields() {
	g.Kind = KindUserGroup
	g.Version = V1
}

// CheckAndSetDefaults checks and sets default values
func (g *UserGroupV1) CheckAndSetDefaults() error {
	g.setStaticFields()
	if err := g.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// UserGroups is a list of UserGroup resources.
type UserGroups []UserGroup

// AsResources returns these groups as resources with labels.
func (g UserGroups) AsResources() (resources ResourcesWithLabels) {
	for _, group := range g {
		resources = append(resources, group)
	}
	return resources
}

// Len returns the slice length.
func (g UserGroups) Len() int { return len(g) }

// Less compares user groups by name.
func (g UserGroups) Less(i, j int) bool { return g[i].GetName() < g[j].GetName() }

// Swap swaps two user groups.
func (g UserGroups) Swap(i, j int) { g[i], g[j] = g[j], g[i] }
