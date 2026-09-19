// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// TestDataJSONFieldValue covers the paths that are reachable without a
// configuration attached to the request, which is how Terraform invokes a
// read and how an update triggered by an unrelated attribute behaves.
func TestDataJSONFieldValue(t *testing.T) {
	res := genericSecretResource("vault_generic_secret")

	t.Run("data_json is decoded", func(t *testing.T) {
		d := res.Data(&terraform.InstanceState{
			ID: "secret/foo",
			Attributes: map[string]string{
				"id":        "secret/foo",
				"path":      "secret/foo",
				"data_json": `{"zip":"zap"}`,
			},
		})

		data, writeNeeded, err := dataJSONFieldValue(d)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !writeNeeded {
			t.Fatal("expected a write to be required for data_json")
		}
		if data["zip"] != "zap" {
			t.Fatalf("unexpected payload %#v", data)
		}
	})

	// Terraform prints resource errors to the console, so a malformed
	// payload must not be echoed back: it holds the secret.
	t.Run("a syntax error does not echo the value", func(t *testing.T) {
		d := res.Data(&terraform.InstanceState{
			ID: "secret/foo",
			Attributes: map[string]string{
				"id":        "secret/foo",
				"path":      "secret/foo",
				"data_json": `{"zip":"s3cr3t`,
			},
		})

		_, _, err := dataJSONFieldValue(d)
		if err == nil {
			t.Fatal("expected a syntax error")
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("error leaks the payload: %s", err)
		}
	})

	// An existing write-only resource updated because some other attribute
	// changed must leave Vault alone: the ephemeral value is not available,
	// and neither erroring nor writing an empty payload is acceptable.
	t.Run("write-only data without a version change is left alone", func(t *testing.T) {
		d := res.Data(&terraform.InstanceState{
			ID: "secret/foo",
			Attributes: map[string]string{
				"id":                   "secret/foo",
				"path":                 "secret/foo",
				"data_json_wo_version": "1",
			},
		})

		buf, writeNeeded, err := dataJSONFieldValue(d)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if writeNeeded {
			t.Fatal("expected no write when data_json_wo_version is unchanged")
		}
		if buf != nil {
			t.Fatalf("expected no payload, got %q", buf)
		}
	})
}

// TestUsesWriteOnlyData pins the signal used during a read, where Terraform
// sends prior state but no configuration.
func TestUsesWriteOnlyData(t *testing.T) {
	res := genericSecretResource("vault_generic_secret")

	for name, tc := range map[string]struct {
		attrs    map[string]string
		expected bool
	}{
		"classic data_json": {
			attrs:    map[string]string{"data_json": `{"zip":"zap"}`},
			expected: false,
		},
		"write-only data": {
			attrs:    map[string]string{consts.FieldDataJSONWOVersion: "2"},
			expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			attrs := map[string]string{"id": "secret/foo", "path": "secret/foo"}
			for k, v := range tc.attrs {
				attrs[k] = v
			}

			d := res.Data(&terraform.InstanceState{ID: "secret/foo", Attributes: attrs})
			if got := usesWriteOnlyData(d); got != tc.expected {
				t.Fatalf("usesWriteOnlyData() = %v, want %v", got, tc.expected)
			}
		})
	}
}
