// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/initdata"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCryptpilotPolicy = `version = "0.1.0"
key_uri = "kbs:///default/openshell/workspace-key"
allow_initialize = true
integrity = false
`

func writeTestInitdata(t *testing.T, policy string) string {
	t.Helper()
	encoded, err := initdata.Encode(`version = "0.1.0"
algorithm = "sha384"
[data]
"cryptpilot.toml" = '''
` + policy + `'''
`)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "initdata")
	require.NoError(t, os.WriteFile(path, []byte(encoded), 0o600))
	return path
}

func TestLoadCryptpilotPolicyFromMeasuredInitdata(t *testing.T) {
	policy, err := loadCryptpilotPolicy(writeTestInitdata(t, testCryptpilotPolicy))
	require.NoError(t, err)
	assert.Equal(t, cryptpilotPolicyVersion, policy.Version)
	assert.Equal(t, "kbs:///default/openshell/workspace-key", policy.KeyURI)
	assert.True(t, policy.AllowInitialize)

	_, err = loadCryptpilotPolicy(writeTestInitdata(t, testCryptpilotPolicy+"unknown = true\n"))
	assert.ErrorContains(t, err, "missing in the target struct")

	missing, err := initdata.Encode("version = \"0.1.0\"\nalgorithm = \"sha384\"\n[data]\n")
	require.NoError(t, err)
	missingPath := filepath.Join(t.TempDir(), "initdata")
	require.NoError(t, os.WriteFile(missingPath, []byte(missing), 0o600))
	_, err = loadCryptpilotPolicy(missingPath)
	assert.ErrorContains(t, err, cryptpilotPolicyName)
}

func TestValidateKBSResourceURI(t *testing.T) {
	assert.NoError(t, validateKBSResourceURI("kbs:///default/openshell/workspace-key"))
	for _, invalid := range []string{
		"https://trustee/key", "kbs://trustee/default/key", "kbs:///too/few", "kbs:///too/many/path/parts", "kbs:///default/type/key?q=1",
	} {
		assert.Error(t, validateKBSResourceURI(invalid), invalid)
	}
}

func cryptpilotStatusJSON(t *testing.T, status, device string) []byte {
	t.Helper()
	data, err := json.Marshal([]cryptpilotStatus{{
		Volume: "peerpod-abc123", VolumePath: "/dev/mapper/peerpod-abc123",
		UnderlayDevice: device, KeyProvider: "kbs", Status: status,
	}})
	require.NoError(t, err)
	return data
}

func testCryptpilotAdapter(t *testing.T, statuses ...string) (*cryptpilotAdapter, *[]string, map[string]bool) {
	t.Helper()
	commands := []string{}
	readOnly := map[string]bool{}
	statusIndex := 0
	adapter := &cryptpilotAdapter{
		policy: cryptpilotPolicy{
			Version: cryptpilotPolicyVersion, KeyURI: "kbs:///default/openshell/workspace-key", AllowInitialize: true,
		},
		runtimeDir: t.TempDir(),
	}
	adapter.run = func(_ context.Context, arguments ...string) ([]byte, error) {
		commands = append(commands, strings.Join(arguments, " "))
		if arguments[0] == "show" {
			if statusIndex >= len(statuses) {
				t.Fatalf("unexpected status query %d", statusIndex)
			}
			status := statuses[statusIndex]
			statusIndex++
			return cryptpilotStatusJSON(t, status, "/dev/vdb"), nil
		}
		return nil, nil
	}
	adapter.getReadOnly = func(_ context.Context, device string) (bool, error) { return readOnly[device], nil }
	adapter.setReadOnly = func(_ context.Context, device string, value bool) error {
		readOnly[device] = value
		return nil
	}
	adapter.waitForMapper = func(context.Context, string) error { return nil }
	adapter.requireBlank = func(context.Context, string) error { return nil }
	return adapter, &commands, readOnly
}

func TestCryptpilotPrepareInitializesAndOpens(t *testing.T) {
	adapter, commands, _ := testCryptpilotAdapter(t, "RequiresInit", "ReadyToOpen")
	prepared, err := adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", false)
	require.NoError(t, err)
	assert.Equal(t, "/dev/mapper/peerpod-abc123", prepared.path)
	assert.True(t, prepared.openedMapperHere)
	assert.Equal(t, []string{
		"show peerpod-abc123 --json", "init peerpod-abc123 --yes", "show peerpod-abc123 --json", "open peerpod-abc123 --check-fs",
	}, *commands)

	content, err := os.ReadFile(filepath.Join(adapter.runtimeDir, "volumes", "peerpod-abc123.toml"))
	require.NoError(t, err)
	var config cryptpilotVolumeConfig
	require.NoError(t, toml.Unmarshal(content, &config))
	assert.Equal(t, "/dev/vdb", config.Device)
	assert.Equal(t, "kbs:///default/openshell/workspace-key", config.Encrypt.KBS.KeyURI)
}

func TestCryptpilotPrepareReadOnlyBoundary(t *testing.T) {
	adapter, commands, modes := testCryptpilotAdapter(t, "ReadyToOpen")
	prepared, err := adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", true)
	require.NoError(t, err)
	assert.True(t, prepared.setRawReadOnlyHere)
	assert.True(t, modes["/dev/vdb"])
	assert.True(t, modes["/dev/mapper/peerpod-abc123"])
	assert.Equal(t, []string{"show peerpod-abc123 --json", "open peerpod-abc123"}, *commands)

	reused, _, reusedModes := testCryptpilotAdapter(t, "Opened")
	reusedModes["/dev/vdb"] = true
	reusedModes["/dev/mapper/peerpod-abc123"] = false
	_, err = reused.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", true)
	assert.ErrorContains(t, err, "mapper device")
}

func TestCryptpilotPrepareFailsClosed(t *testing.T) {
	adapter, _, _ := testCryptpilotAdapter(t, "RequiresInit")
	_, err := adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", true)
	assert.ErrorContains(t, err, "not initialized")

	_, err = adapter.prepare(context.Background(), "vol-abc", "/dev/vdb", "ext4", false)
	assert.ErrorContains(t, err, "Alibaba Cloud disk ID")
	_, err = adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "xfs", false)
	assert.ErrorContains(t, err, "require ext4")

	adapter, _, _ = testCryptpilotAdapter(t, "ReadyToOpen")
	adapter.run = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
	_, err = adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", false)
	assert.Error(t, err)

	adapter, _, _ = testCryptpilotAdapter(t, "Initializing")
	_, err = adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", false)
	assert.ErrorContains(t, err, "cannot open from status Initializing")
}

func TestCryptpilotAmbiguousOpenRetainsCleanupOwnership(t *testing.T) {
	adapter, commands, _ := testCryptpilotAdapter(t, "ReadyToOpen", "Opened")
	statusRun := adapter.run
	adapter.run = func(ctx context.Context, arguments ...string) ([]byte, error) {
		if arguments[0] == "open" {
			*commands = append(*commands, strings.Join(arguments, " "))
			return nil, errors.New("client timeout")
		}
		return statusRun(ctx, arguments...)
	}
	prepared, err := adapter.prepare(context.Background(), "d-abc123", "/dev/vdb", "ext4", false)
	assert.ErrorContains(t, err, "client timeout")
	assert.True(t, prepared.openedMapperHere, "the mapper appeared after this call began")
}
