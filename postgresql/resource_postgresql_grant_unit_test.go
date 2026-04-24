package postgresql

import (
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func buildGrantResourceData(t *testing.T, objectType string, wanted ...string) *schema.ResourceData {
	testSchema := map[string]*schema.Schema{
		"object_type": {Type: schema.TypeString},
		"privileges": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{Type: schema.TypeString},
			Set:  schema.HashString,
		},
	}
	d := schema.TestResourceDataRaw(t, testSchema, map[string]any{
		"object_type": objectType,
	})
	if err := d.Set("privileges", buildPrivilegesSet(toAnySlice(wanted)...)); err != nil {
		t.Fatalf("set privileges: %v", err)
	}
	return d
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func setToSortedStrings(s *schema.Set) []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, s.Len())
	for _, v := range s.List() {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func TestComputeDriftedPrivileges(t *testing.T) {
	cases := []struct {
		name          string
		wanted        []string
		perObject     map[string][]string
		expectedState []string
		expectedDrift []string
	}{
		{
			name:   "all objects match desired",
			wanted: []string{"SELECT", "INSERT"},
			perObject: map[string][]string{
				"table_a": {"SELECT", "INSERT"},
				"table_b": {"SELECT", "INSERT"},
			},
			expectedState: []string{"INSERT", "SELECT"},
			expectedDrift: nil,
		},
		{
			name:   "one object has extra privilege",
			wanted: []string{"SELECT", "INSERT"},
			perObject: map[string][]string{
				"table_a": {"SELECT", "INSERT", "UPDATE"},
				"table_b": {"SELECT", "INSERT"},
			},
			expectedState: []string{"INSERT", "SELECT", "UPDATE"},
			expectedDrift: []string{"table_a"},
		},
		{
			name:   "one object missing a privilege",
			wanted: []string{"SELECT", "INSERT"},
			perObject: map[string][]string{
				"table_a": {"SELECT", "INSERT"},
				"table_b": {"SELECT"},
			},
			expectedState: []string{"SELECT"},
			expectedDrift: []string{"table_b"},
		},
		{
			name:   "heterogeneous: missing on one, extra on another",
			wanted: []string{"SELECT", "INSERT"},
			perObject: map[string][]string{
				"table_a": {"SELECT", "INSERT", "UPDATE"},
				"table_b": {"SELECT"},
				"table_c": {"SELECT", "INSERT"},
			},
			expectedState: []string{"SELECT", "UPDATE"},
			expectedDrift: []string{"table_a", "table_b"},
		},
		{
			name:   "all objects have empty privileges",
			wanted: []string{"SELECT"},
			perObject: map[string][]string{
				"table_a": {},
				"table_b": {},
			},
			expectedState: []string{},
			expectedDrift: []string{"table_a", "table_b"},
		},
		{
			name:   "drifting objects are sorted deterministically",
			wanted: []string{"SELECT"},
			perObject: map[string][]string{
				"z_table": {},
				"a_table": {},
				"m_table": {},
			},
			expectedState: []string{},
			expectedDrift: []string{"a_table", "m_table", "z_table"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := buildGrantResourceData(t, "table", tc.wanted...)
			perObject := make(map[string]*schema.Set, len(tc.perObject))
			for name, privs := range tc.perObject {
				perObject[name] = buildPrivilegesSet(toAnySlice(privs)...)
			}

			state, drifting := computeDriftedPrivileges(perObject, d)

			assert.Equal(t, tc.expectedDrift, drifting, "drifting objects")
			assert.Equal(t, tc.expectedState, setToSortedStrings(state), "state privileges")
		})
	}
}

func TestComputeDriftedPrivileges_implicitAllIsNotDrift(t *testing.T) {
	// When the user asks for ALL on tables, the implicit expansion
	// {SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN} must
	// be considered equal to ALL, so no drift should be reported.
	d := buildGrantResourceData(t, "table", "ALL")
	perObject := map[string]*schema.Set{
		"table_a": buildPrivilegesSet(
			"SELECT", "INSERT", "UPDATE", "DELETE",
			"TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN",
		),
	}

	_, drifting := computeDriftedPrivileges(perObject, d)
	assert.Empty(t, drifting)
}
