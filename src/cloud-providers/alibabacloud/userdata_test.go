// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"math/rand"
	"strings"
	"testing"
)

func TestEncodeUserData(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		compressed bool
	}{
		{
			name:       "at compression threshold",
			data:       strings.Repeat("x", maxUserDataPayloadBytes),
			compressed: false,
		},
		{
			name:       "over compression threshold",
			data:       strings.Repeat("x", maxUserDataPayloadBytes+1),
			compressed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := encodeUserData(test.data)
			if err != nil {
				t.Fatal(err)
			}
			encodedAgain, err := encodeUserData(test.data)
			if err != nil {
				t.Fatal(err)
			}
			if encodedAgain != encoded {
				t.Fatal("user data encoding is not deterministic")
			}
			payload, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}

			if !test.compressed {
				if string(payload) != test.data {
					t.Fatal("small user data changed")
				}
				return
			}

			reader, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if string(decoded) != test.data {
				t.Fatal("compressed user data did not round-trip")
			}
		})
	}
}

func TestEncodeUserDataRejectsOversizedCompressedPayload(t *testing.T) {
	payload := make([]byte, maxUserDataPayloadBytes*2)
	if _, err := rand.New(rand.NewSource(1)).Read(payload); err != nil {
		t.Fatal(err)
	}

	_, err := encodeUserData(string(payload))
	if err == nil || !strings.Contains(err.Error(), "after compression") {
		t.Fatalf("expected compressed-size error, got %v", err)
	}
}
