// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/initdata"
	toml "github.com/pelletier/go-toml/v2"
)

const (
	cryptpilotPolicyName     = "cryptpilot.toml"
	cryptpilotPolicyVersion  = "0.1.0"
	cryptpilotBinary         = "/usr/bin/cryptpilot-crypt"
	cryptpilotRuntimeDir     = "/run/peerpod/cryptpilot"
	cryptpilotInitdataPath   = "/run/peerpod/initdata"
	cryptpilotMaxInitdata    = 2 << 20
	cryptpilotMapperWaitTime = 30 * time.Second
)

type cryptpilotPolicy struct {
	Version         string `toml:"version"`
	KeyURI          string `toml:"key_uri"`
	AllowInitialize bool   `toml:"allow_initialize"`
	Integrity       bool   `toml:"integrity"`
}

type cryptpilotVolumeConfig struct {
	Volume    string            `toml:"volume"`
	Device    string            `toml:"dev"`
	AutoOpen  bool              `toml:"auto_open"`
	MakeFS    string            `toml:"makefs"`
	Integrity bool              `toml:"integrity"`
	Encrypt   cryptpilotEncrypt `toml:"encrypt"`
}

type cryptpilotEncrypt struct {
	KBS cryptpilotKBS `toml:"kbs"`
}

type cryptpilotKBS struct {
	CDHType string `toml:"cdh_type"`
	KeyURI  string `toml:"key_uri"`
}

type cryptpilotStatus struct {
	Volume         string `json:"volume"`
	VolumePath     string `json:"volume_path"`
	UnderlayDevice string `json:"underlay_device"`
	KeyProvider    string `json:"key_provider"`
	Status         string `json:"status"`
	Description    string `json:"description"`
}

// cryptpilotPreparedDevice contains only guest-local state. It is deliberately
// not part of the cloud provider or direct-volume metadata contract.
type cryptpilotPreparedDevice struct {
	path               string
	name               string
	rawDevice          string
	openedMapperHere   bool
	setRawReadOnlyHere bool
}

type cryptpilotAdapter struct {
	policy        cryptpilotPolicy
	runtimeDir    string
	binary        string
	run           func(context.Context, ...string) ([]byte, error)
	getReadOnly   func(context.Context, string) (bool, error)
	setReadOnly   func(context.Context, string, bool) error
	waitForMapper func(context.Context, string) error
	mapperExists  func(string) (bool, error)
	requireBlank  func(context.Context, string) error
}

func loadCryptpilotPolicy(path string) (cryptpilotPolicy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return cryptpilotPolicy{}, fmt.Errorf("read measured initdata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > cryptpilotMaxInitdata {
		return cryptpilotPolicy{}, fmt.Errorf("measured initdata must be a regular file no larger than %d bytes", cryptpilotMaxInitdata)
	}
	file, err := os.Open(path)
	if err != nil {
		return cryptpilotPolicy{}, fmt.Errorf("open measured initdata: %w", err)
	}
	defer file.Close()

	parsed, err := initdata.Parse(io.LimitReader(file, cryptpilotMaxInitdata+1))
	if err != nil {
		return cryptpilotPolicy{}, fmt.Errorf("parse measured initdata: %w", err)
	}
	raw, ok := parsed.Body.Data[cryptpilotPolicyName]
	if !ok {
		return cryptpilotPolicy{}, fmt.Errorf("measured initdata is missing %s", cryptpilotPolicyName)
	}
	var policy cryptpilotPolicy
	decoder := toml.NewDecoder(strings.NewReader(raw)).DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return cryptpilotPolicy{}, fmt.Errorf("parse %s: %w", cryptpilotPolicyName, err)
	}
	if policy.Version != cryptpilotPolicyVersion {
		return cryptpilotPolicy{}, fmt.Errorf("unsupported CryptPilot policy version %q", policy.Version)
	}
	if err := validateKBSResourceURI(policy.KeyURI); err != nil {
		return cryptpilotPolicy{}, err
	}
	return policy, nil
}

func validateKBSResourceURI(value string) error {
	resource, err := url.Parse(value)
	if err != nil || resource.Scheme != "kbs" || resource.Host != "" || resource.RawQuery != "" ||
		resource.Fragment != "" || !strings.HasPrefix(value, "kbs:///") {
		return errors.New("key_uri must be a kbs:/// resource URI")
	}
	parts := strings.Split(strings.TrimPrefix(resource.Path, "/"), "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return errors.New("key_uri must identify a KBS repository, type, and tag")
	}
	return nil
}

func newCryptpilotAdapter(policy cryptpilotPolicy) *cryptpilotAdapter {
	adapter := &cryptpilotAdapter{
		policy:       policy,
		runtimeDir:   cryptpilotRuntimeDir,
		binary:       cryptpilotBinary,
		getReadOnly:  blockDeviceReadOnly,
		setReadOnly:  setBlockDeviceMode,
		mapperExists: blockDeviceExists,
		requireBlank: requireBlankBlockDevice,
	}
	adapter.run = adapter.runCommand
	adapter.waitForMapper = waitForCryptpilotMapper
	return adapter
}

func (a *cryptpilotAdapter) cleanup(ctx context.Context, prepared *cryptpilotPreparedDevice) error {
	if prepared == nil {
		return nil
	}
	if prepared.openedMapperHere {
		exists, err := a.mapperExists(prepared.path)
		if err != nil {
			return fmt.Errorf("inspect CryptPilot mapper %s: %w", prepared.path, err)
		}
		if exists {
			_, closeErr := a.run(ctx, "close", prepared.name)
			exists, statErr := a.mapperExists(prepared.path)
			if statErr != nil {
				return errors.Join(closeErr, statErr)
			}
			if closeErr != nil && exists {
				return fmt.Errorf("close CryptPilot mapper %s: %w", prepared.name, closeErr)
			}
			if exists {
				return fmt.Errorf("CryptPilot mapper %s remains open after close", prepared.name)
			}
		}
		prepared.openedMapperHere = false
	}
	if prepared.setRawReadOnlyHere {
		if err := a.setReadOnly(ctx, prepared.rawDevice, false); err != nil {
			return err
		}
		readOnly, err := a.getReadOnly(ctx, prepared.rawDevice)
		if err != nil {
			return err
		}
		if readOnly {
			return fmt.Errorf("underlay device %s remains readonly", prepared.rawDevice)
		}
		prepared.setRawReadOnlyHere = false
	}
	return nil
}

func (a *cryptpilotAdapter) prepare(ctx context.Context, diskID, device, fsType string, readOnly bool) (*cryptpilotPreparedDevice, error) {
	if !alibabaDiskIDPattern.MatchString(diskID) {
		return nil, fmt.Errorf("CryptPilot requires an Alibaba Cloud disk ID, got %q", diskID)
	}
	if fsType != "ext4" {
		return nil, fmt.Errorf("CryptPilot volumes require ext4, got %q", fsType)
	}

	name := "peerpod-" + normalizeAlibabaDiskID(diskID)
	prepared := &cryptpilotPreparedDevice{
		path:      filepath.Join("/dev/mapper", name),
		name:      name,
		rawDevice: device,
	}
	if err := a.writeVolumeConfig(prepared, device); err != nil {
		return prepared, err
	}
	status, err := a.status(ctx, prepared)
	if err != nil {
		return prepared, err
	}

	switch status.Status {
	case "RequiresInit":
		if readOnly {
			return prepared, fmt.Errorf("readonly CryptPilot volume %s is not initialized", name)
		}
		if !a.policy.AllowInitialize {
			return prepared, fmt.Errorf("CryptPilot volume %s requires initialization but allow_initialize is false", name)
		}
		if err := a.requireBlank(ctx, device); err != nil {
			return prepared, fmt.Errorf("refusing to initialize %s: %w", diskID, err)
		}
		_, initErr := a.run(ctx, "init", name, "--yes")
		status, err = a.status(ctx, prepared)
		if err != nil {
			return prepared, errors.Join(initErr, err)
		}
		if initErr != nil && status.Status != "ReadyToOpen" && status.Status != "Opened" {
			return prepared, initErr
		}
		if status.Status != "ReadyToOpen" && status.Status != "Opened" {
			return prepared, fmt.Errorf("CryptPilot volume %s has status %s after initialization", name, status.Status)
		}
		prepared.openedMapperHere = status.Status == "Opened"
	case "ReadyToOpen", "Opened":
	default:
		return prepared, fmt.Errorf("CryptPilot volume %s cannot open from status %s: %s", name, status.Status, status.Description)
	}

	if status.Status == "Opened" {
		if err := a.waitForMapper(ctx, prepared.path); err != nil {
			return prepared, err
		}
		if readOnly {
			if err := a.verifyReadOnly(ctx, prepared); err != nil {
				return prepared, err
			}
		}
		return prepared, nil
	}

	if readOnly {
		underlayReadOnly, err := a.getReadOnly(ctx, device)
		if err != nil {
			return prepared, err
		}
		if !underlayReadOnly {
			prepared.setRawReadOnlyHere = true
			if err := a.setReadOnly(ctx, device, true); err != nil {
				return prepared, err
			}
		}
	}
	arguments := []string{"open", name}
	if !readOnly {
		arguments = append(arguments, "--check-fs")
	}
	// The status above proves this mapper was not open before this operation.
	// Claim ownership before the command so an applied-but-unreported open can
	// still be closed by rollback.
	prepared.openedMapperHere = true
	if _, err := a.run(ctx, arguments...); err != nil {
		current, statusErr := a.status(ctx, prepared)
		if statusErr == nil && current.Status != "Opened" {
			prepared.openedMapperHere = false
		}
		return prepared, errors.Join(err, statusErr)
	}
	if err := a.waitForMapper(ctx, prepared.path); err != nil {
		return prepared, err
	}
	if readOnly {
		if err := a.setReadOnly(ctx, prepared.path, true); err != nil {
			return prepared, err
		}
		if err := a.verifyReadOnly(ctx, prepared); err != nil {
			return prepared, err
		}
	}
	return prepared, nil
}

func (a *cryptpilotAdapter) verifyReadOnly(ctx context.Context, prepared *cryptpilotPreparedDevice) error {
	for label, device := range map[string]string{"underlay": prepared.rawDevice, "mapper": prepared.path} {
		readOnly, err := a.getReadOnly(ctx, device)
		if err != nil {
			return err
		}
		if !readOnly {
			return fmt.Errorf("CryptPilot %s device %s is writable", label, device)
		}
	}
	return nil
}

func (a *cryptpilotAdapter) status(ctx context.Context, prepared *cryptpilotPreparedDevice) (cryptpilotStatus, error) {
	output, err := a.run(ctx, "show", prepared.name, "--json")
	if err != nil {
		return cryptpilotStatus{}, err
	}
	var statuses []cryptpilotStatus
	if err := json.Unmarshal(output, &statuses); err != nil {
		return cryptpilotStatus{}, fmt.Errorf("parse CryptPilot status: %w", err)
	}
	if len(statuses) != 1 {
		return cryptpilotStatus{}, fmt.Errorf("CryptPilot returned %d statuses for %s", len(statuses), prepared.name)
	}
	status := statuses[0]
	if status.Volume != prepared.name || filepath.Clean(status.UnderlayDevice) != filepath.Clean(prepared.rawDevice) ||
		filepath.Clean(status.VolumePath) != filepath.Clean(prepared.path) || status.KeyProvider != "kbs" {
		return cryptpilotStatus{}, fmt.Errorf("CryptPilot status does not match volume %s", prepared.name)
	}
	return status, nil
}

func (a *cryptpilotAdapter) writeVolumeConfig(prepared *cryptpilotPreparedDevice, device string) error {
	directory := filepath.Join(a.runtimeDir, "volumes")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create CryptPilot config directory: %w", err)
	}
	content, err := toml.Marshal(cryptpilotVolumeConfig{
		Volume: prepared.name, Device: device, AutoOpen: false, MakeFS: "ext4", Integrity: a.policy.Integrity,
		Encrypt: cryptpilotEncrypt{KBS: cryptpilotKBS{CDHType: "daemon", KeyURI: a.policy.KeyURI}},
	})
	if err != nil {
		return fmt.Errorf("marshal CryptPilot volume config: %w", err)
	}
	path := filepath.Join(directory, prepared.name+".toml")
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("existing CryptPilot config %s conflicts with %s", path, prepared.name)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read CryptPilot volume config: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".volume-*.toml")
	if err != nil {
		return fmt.Errorf("create CryptPilot volume config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write CryptPilot volume config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish CryptPilot volume config: %w", err)
	}
	return nil
}

func (a *cryptpilotAdapter) runCommand(ctx context.Context, arguments ...string) ([]byte, error) {
	args := append([]string{"-c", a.runtimeDir}, arguments...)
	command := exec.CommandContext(ctx, a.binary, args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("cryptpilot-crypt %s failed: %s: %w", strings.Join(arguments, " "), strings.TrimSpace(stderr.String()), err)
	}
	return output, nil
}

func blockDeviceReadOnly(ctx context.Context, device string) (bool, error) {
	output, err := exec.CommandContext(ctx, "blockdev", "--getro", device).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("query readonly state for %s: %s: %w", device, strings.TrimSpace(string(output)), err)
	}
	value := strings.TrimSpace(string(output))
	if value != "0" && value != "1" {
		return false, fmt.Errorf("invalid readonly state %q for %s", value, device)
	}
	return value == "1", nil
}

func setBlockDeviceMode(ctx context.Context, device string, readOnly bool) error {
	mode := "--setrw"
	if readOnly {
		mode = "--setro"
	}
	output, err := exec.CommandContext(ctx, "blockdev", mode, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set block device %s mode %s: %s: %w", device, mode, strings.TrimSpace(string(output)), err)
	}
	return nil
}

func requireBlankBlockDevice(ctx context.Context, device string) error {
	name := filepath.Base(device)
	if isRootOrMountedDevice(name) || hasPartitions(name) {
		return errors.New("device is mounted or has partitions")
	}
	output, err := exec.CommandContext(ctx, "blkid", "-p", device).CombinedOutput()
	if err == nil || len(bytes.TrimSpace(output)) != 0 {
		return fmt.Errorf("device has an existing signature: %s", strings.TrimSpace(string(output)))
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
		return fmt.Errorf("inspect device signature: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func waitForCryptpilotMapper(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, cryptpilotMapperWaitTime)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for CryptPilot mapper %s: %w", path, ctx.Err())
		case <-ticker.C:
		}
	}
}

func blockDeviceExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0, nil
}
