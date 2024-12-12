package tunneler

import (
	"encoding/json"
	"testing"
)

func TestWireGuardJSONTags(t *testing.T) {
	config := &Config{
		WireGuard: &WireGuard{
			Port:             51820,
			MTU:              1420,
			ServerPrivateKey: "server-private",
			ClientPublicKey:  "client-public",
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	var wireGuardConfig map[string]interface{}
	if err := json.Unmarshal(got["wireguard"], &wireGuardConfig); err != nil {
		t.Fatal(err)
	}

	if wireGuardConfig["server-private-key"] != config.WireGuard.ServerPrivateKey {
		t.Fatalf("server private key serialized with wrong JSON tag: %s", data)
	}
	if wireGuardConfig["client-public-key"] != config.WireGuard.ClientPublicKey {
		t.Fatalf("client public key serialized with wrong JSON tag: %s", data)
	}
	if _, ok := wireGuardConfig["server-public-key"]; ok {
		t.Fatalf("server private key serialized with obsolete public-key tag: %s", data)
	}
	if _, ok := wireGuardConfig["client-private-key"]; ok {
		t.Fatalf("client public key serialized with obsolete private-key tag: %s", data)
	}
}
