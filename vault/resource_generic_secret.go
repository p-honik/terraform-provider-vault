// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const latestSecretVersion = -1

func genericSecretResource(name string) *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericSecretResourceWrite,
		Update: genericSecretResourceWrite,
		Delete: genericSecretResourceDelete,
		Read:   provider.ReadWrapper(genericSecretResourceRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceGenericSecretMigrateState,

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written.",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "JSON-encoded secret data to write. This is required if data_json_wo is not set.",
				// We rebuild the attached JSON string to a simple singleline
				// string. This makes terraform not want to change when an extra
				// space is included in the JSON string. It is also necesarry
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				Sensitive:    true,
				ExactlyOneOf: []string{consts.FieldDataJSON, consts.FieldDataJSONWO},
			},
			consts.FieldDataJSONWO: {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Write-only JSON-encoded secret data to write. This is required if data_json is not set. This property is write-only and will not be read from the API.",
				ExactlyOneOf: []string{consts.FieldDataJSON, consts.FieldDataJSONWO},
				// The version is what tells a read that the data must not be
				// stored in state, so it is mandatory here rather than merely
				// being the trigger for updating the value.
				RequiredWith: []string{consts.FieldDataJSONWOVersion},
			},
			consts.FieldDataJSONWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "The version of data_json_wo. For more info see updating write-only attributes.",
				RequiredWith: []string{consts.FieldDataJSONWO},
				ValidateFunc: validation.IntAtLeast(1),
			},

			"disable_read": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't attempt to read the token from Vault if true; drift won't be detected.",
			},

			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			"delete_all_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Only applicable for kv-v2 stores. If set, permanently deletes all versions for the specified key.",
			},
		},
	}
}

// dataJSONFieldValue returns the JSON-encoded data supplied via either the
// classic data_json field or the write-only data_json_wo field, shared by
// vault_generic_secret and vault_generic_endpoint.
//
// The second return value reports whether Vault needs to be written at all.
// A write-only value only reaches the provider while data_json_wo_version
// changes, so an update triggered by an unrelated field such as disable_read
// must leave the data already stored in Vault alone rather than failing or
// writing an empty payload.
func dataJSONFieldValue(d *schema.ResourceData) ([]byte, bool, error) {
	if v, ok := d.GetOk(consts.FieldDataJSON); ok {
		return []byte(v.(string)), true, nil
	}

	if !d.IsNewResource() && !d.HasChange(consts.FieldDataJSONWOVersion) {
		return nil, false, nil
	}

	woVal, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldDataJSONWO))
	// A request that carries no configuration at all yields an unknown value
	// rather than a null one, so both cases must be rejected before AsString.
	if woVal.IsKnown() && !woVal.IsNull() {
		return []byte(woVal.AsString()), true, nil
	}

	return nil, false, fmt.Errorf("either %s or %s must be set",
		consts.FieldDataJSON, consts.FieldDataJSONWO)
}

// usesWriteOnlyData reports whether the data held in Vault was supplied
// through the write-only data_json_wo field, in which case it must never be
// read back into state.
//
// data_json_wo_version is an ordinary attribute, so unlike the write-only
// value itself it is still readable during a read, where Terraform sends the
// prior state but no configuration at all.
func usesWriteOnlyData(d *schema.ResourceData) bool {
	return d.Get(consts.FieldDataJSONWOVersion).(int) > 0
}

func ValidateDataJSONFunc(name string) func(c interface{}, k string) ([]string, []error) {
	return func(c interface{}, k string) ([]string, []error) {
		return validateDataJSON(name, c.(string), k)
	}
}

func validateDataJSON(name string, data, k string) ([]string, []error) {
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(data), &dataMap)
	if err != nil {
		log.Printf("[ERROR] Failed to validate JSON data, resource=%q, key=%q, err=%s",
			name, k, err)
		return nil, []error{err}
	}
	return nil, nil
}

// NormalizeDataJSONFunc returns a NormalizeFunc that normalizes the JSON data
// for storage in the TF state for a given resource denoted by `name`.
func NormalizeDataJSONFunc(name string) func(c interface{}) string {
	return func(c interface{}) string {
		data := c.(string)
		result, err := normalizeDataJSON(data)
		if err != nil {
			// The validate function should've prevented invalid JSON ever getting here.
			log.Printf("[WARN] Failed to normalize JSON data, resource=%q, err=%s", name, err)
		}
		return result
	}
}

func normalizeDataJSON(data string) (string, error) {
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(data), &dataMap)
	if err != nil {
		return "", err
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		return data, err
	}
	return string(ret), nil
}

func genericSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	buf, writeNeeded, err := dataJSONFieldValue(d)
	if err != nil {
		return err
	}
	if !writeNeeded {
		return genericSecretResourceRead(d, meta)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(buf, &data); err != nil {
		return fmt.Errorf("data_json %#v syntax error: %s", string(buf), err)
	}

	path := d.Get(consts.FieldPath).(string)
	originalPath := path // if the path belongs to a v2 endpoint, it will be modified
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}

	}

	if _, err := util.RetryWrite(client, path, data, util.DefaultRequestOpts()); err != nil {
		return err
	}

	d.SetId(originalPath)

	return genericSecretResourceRead(d, meta)
}

func genericSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		base := "data"
		deleteAllVersions := d.Get("delete_all_versions").(bool)
		if deleteAllVersions {
			base = consts.FieldMetadata
		}
		path = addPrefixToVKVPath(path, mountPath, base)
	}

	log.Printf("[DEBUG] Deleting vault_generic_secret from %q", path)
	_, err = client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func genericSecretResourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	usingWriteOnly := usesWriteOnlyData(d)

	var data map[string]interface{}
	shouldRead := !d.Get("disable_read").(bool)

	path := d.Id()

	if shouldRead {
		log.Printf("[DEBUG] Reading %s from Vault", path)
		secret, err := versionedSecret(latestSecretVersion, path, client)
		if err != nil {
			return fmt.Errorf("error reading from Vault: %s", err)
		}
		if secret == nil {
			log.Printf("[WARN] secret (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		data = secret.Data

		if !usingWriteOnly {
			jsonData, err := json.Marshal(secret.Data)
			if err != nil {
				return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
			}

			if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
				return err
			}
		}
		if err := d.Set(consts.FieldPath, path); err != nil {
			return err
		}
	} else {
		// Populate data from data_json from state. Write-only data is not
		// held in state, so there is nothing to reconstruct it from.
		if !usingWriteOnly {
			err := json.Unmarshal([]byte(d.Get(consts.FieldDataJSON).(string)), &data)
			if err != nil {
				return fmt.Errorf("data_json %#v syntax error: %s", d.Get(consts.FieldDataJSON), err)
			}
		}
		log.Printf("[WARN] vault_generic_secret does not refresh when disable_read is set to true")
	}

	if err := d.Set("disable_read", !shouldRead); err != nil {
		return err
	}

	if usingWriteOnly {
		// "data" is Computed, so a value written while the configuration
		// still used data_json would otherwise survive in state forever
		// once it switches to data_json_wo.
		if err := d.Set("data", map[string]interface{}{}); err != nil {
			return err
		}
	} else {
		dataMap := serializeDataMapToString(data)
		if err := d.Set("data", dataMap); err != nil {
			return err
		}
	}

	if err := d.Set("delete_all_versions", d.Get("delete_all_versions")); err != nil {
		return err
	}

	return nil
}

func serializeDataMapToString(data map[string]interface{}) map[string]string {
	// Since our "data" map can only contain string values, we
	// will take strings from Data and write them in as-is,
	// and write everything else in as a JSON serialization of
	// whatever value we get so that complex types can be
	// passed around and processed elsewhere if desired.
	// Note: This is a different map to jsonData, as this can only
	// contain strings
	dataMap := map[string]string{}
	for k, v := range data {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			// Again ignoring error because we know this value
			// came from JSON in the first place and so must be valid.
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
	}
	return dataMap
}
