// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	cri "github.com/containerd/containerd/pkg/cri/annotations"
	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/adaptor/proxy"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/forwarder"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/paths"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/tlsutil"
	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/util/cloudinit"
)

type mockProvider struct{}

func (p *mockProvider) CreateInstance(ctx context.Context, podName, sandboxID string, cloudConfig cloudinit.CloudConfigGenerator, spec provider.InstanceTypeSpec) (*provider.Instance, error) {
	return &provider.Instance{
		Name: "abc",
		ID:   fmt.Sprintf("%s-%.8s", podName, sandboxID),
		IPs: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
		},
	}, nil
}

func (p *mockProvider) DeleteInstance(ctx context.Context, instanceID string) error {
	return nil
}

func (p *mockProvider) Teardown() error {
	return nil
}

func (p *mockProvider) ConfigVerifier() error {
	return nil
}

func (p *mockProvider) SelectInstanceType(ctx context.Context, vCPU int64, memory int64) (instanceType string, err error) {
	return "", nil
}

type mockProxy struct {
	readyCh    chan struct{}
	stopCh     chan struct{}
	socketPath string
}

func (p *mockProxy) Start(ctx context.Context, serverURL *url.URL) error {
	close(p.readyCh)
	<-p.stopCh
	return nil
}

func (p *mockProxy) Ready() chan struct{} {
	return p.readyCh
}

func (p *mockProxy) Shutdown() error {
	close(p.stopCh)
	return nil
}

func (p *mockProxy) ClientCA() (certPEM []byte) {
	return nil
}

func (p *mockProxy) CAService() tlsutil.CAService {
	return nil
}

type mockProxyFactory struct {
	podsDir       string
	directVolumes *util.DirectVolumeResolution
}

func (f *mockProxyFactory) New(serverName, socketPath string, directVolumes *util.DirectVolumeResolution) proxy.AgentProxy {
	f.directVolumes = directVolumes
	return &mockProxy{
		socketPath: socketPath,
		readyCh:    make(chan struct{}),
		stopCh:     make(chan struct{}),
	}
}

type mockWorkerNode struct{}

func (n mockWorkerNode) Inspect(nsPath string) (*tunneler.Config, error) {
	return &tunneler.Config{
		TunnelType:          podnetwork.DefaultTunnelType,
		Index:               0,
		ExternalNetViaPodVM: false,
	}, nil
}

func (n *mockWorkerNode) Setup(nsPath string, podNodeIPs []netip.Addr, config *tunneler.Config) error {
	return nil
}

func (n *mockWorkerNode) Teardown(nsPath string, config *tunneler.Config) error {
	return nil
}

func TestCloudService(t *testing.T) {

	ctx := context.Background()
	dir := t.TempDir()

	proxyFactory := &mockProxyFactory{
		podsDir: dir,
	}

	cfg := &ServerConfig{
		PodsDir:       dir,
		ForwarderPort: forwarder.DefaultListenPort,
	}

	// false, "", "", "", "", "", dir, forwarder.DefaultListenPort, ""
	s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg)

	assert.NotNil(t, s)

	sandboxID := "123"
	sandboxNS := "default"
	sandboxName := "mypod"

	req := &pb.CreateVMRequest{
		Id: sandboxID,
		Annotations: map[string]string{
			cri.SandboxNamespace: sandboxNS,
			cri.SandboxName:      sandboxName,
		},
	}

	res1, err := s.CreateVM(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, res1)
	assert.Contains(t, res1.AgentSocketPath, dir)
	assert.NotNil(t, proxyFactory.directVolumes)

	res2, err := s.StartVM(ctx, &pb.StartVMRequest{Id: sandboxID})

	assert.NoError(t, err)
	assert.NotNil(t, res2)

	res3, err := s.StopVM(ctx, &pb.StopVMRequest{Id: sandboxID})

	assert.NoError(t, err)
	assert.NotNil(t, res3)
}

func TestCreateVMTLSProfilePropagation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	proxyFactory := &mockProxyFactory{podsDir: dir}

	t.Run("TLS profile written only to guest cloud config when TLSConfig is set", func(t *testing.T) {
		cfg := &ServerConfig{
			PodsDir:       dir,
			ForwarderPort: forwarder.DefaultListenPort,
			TLSConfig: &tlsutil.TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
		}

		s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg).(*cloudService)

		req := &pb.CreateVMRequest{
			Id: "tls-test-sandbox",
			Annotations: map[string]string{
				cri.SandboxNamespace: "default",
				cri.SandboxName:      "tls-test-pod",
			},
		}

		_, err := s.CreateVM(ctx, req)
		require.NoError(t, err)

		daemonCfg := daemonConfigForSandbox(t, s, "tls-test-sandbox")
		_, err = os.Stat(filepath.Join(dir, "tls-test-sandbox", "apf.json"))
		require.ErrorIs(t, err, os.ErrNotExist)

		assert.Equal(t, "VersionTLS13", daemonCfg.MinTLSVersion)
		assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, daemonCfg.CipherSuites)
	})

	t.Run("TLS profile fields absent from guest cloud config when TLSConfig is nil", func(t *testing.T) {
		cfg := &ServerConfig{
			PodsDir:       dir,
			ForwarderPort: forwarder.DefaultListenPort,
			TLSConfig:     nil,
		}

		s := NewService(&mockProvider{}, proxyFactory, &mockWorkerNode{}, cfg).(*cloudService)

		req := &pb.CreateVMRequest{
			Id: "notls-test-sandbox",
			Annotations: map[string]string{
				cri.SandboxNamespace: "default",
				cri.SandboxName:      "notls-test-pod",
			},
		}

		_, err := s.CreateVM(ctx, req)
		require.NoError(t, err)

		daemonCfg := daemonConfigForSandbox(t, s, "notls-test-sandbox")
		_, err = os.Stat(filepath.Join(dir, "notls-test-sandbox", "apf.json"))
		require.ErrorIs(t, err, os.ErrNotExist)

		assert.Empty(t, daemonCfg.MinTLSVersion)
		assert.Empty(t, daemonCfg.CipherSuites)
	})
}

func daemonConfigForSandbox(t *testing.T, service *cloudService, id sandboxID) forwarder.Config {
	t.Helper()
	sandbox, err := service.getSandbox(id)
	require.NoError(t, err)
	for _, file := range sandbox.cloudConfig.WriteFiles {
		if file.Path != forwarder.DefaultConfigPath {
			continue
		}
		var config forwarder.Config
		require.NoError(t, json.Unmarshal([]byte(file.Content), &config))
		return config
	}
	t.Fatalf("sandbox %s has no APF guest configuration", id)
	return forwarder.Config{}
}

func TestCreateVMImagePullSecretsCanBeDisabled(t *testing.T) {
	for _, test := range []struct {
		name     string
		disabled bool
		wantAuth bool
	}{
		{name: "upstream default", wantAuth: true},
		{name: "confidential deployment", disabled: true, wantAuth: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			service := NewService(&mockProvider{}, &mockProxyFactory{podsDir: dir}, &mockWorkerNode{}, &ServerConfig{
				PodsDir: dir, ForwarderPort: forwarder.DefaultListenPort,
				DisableImagePullSecrets: test.disabled,
			}).(*cloudService)
			service.getImagePullSecrets = func(string, string) ([]byte, error) {
				return []byte(`{"auths":{"registry.example":{"auth":"sensitive"}}}`), nil
			}
			id := sandboxID("image-auth-test")
			_, err := service.CreateVM(context.Background(), &pb.CreateVMRequest{
				Id: string(id),
				Annotations: map[string]string{
					cri.SandboxNamespace: "default",
					cri.SandboxName:      "image-auth-pod",
				},
			})
			require.NoError(t, err)
			sandbox, err := service.getSandbox(id)
			require.NoError(t, err)
			found := false
			for _, file := range sandbox.cloudConfig.WriteFiles {
				if file.Path == paths.AuthFilePath {
					found = true
				}
			}
			assert.Equal(t, test.wantAuth, found)
		})
	}
}
