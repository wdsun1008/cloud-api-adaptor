// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package userdata

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/require"
)

func gzipData(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestDecodeAlibabaCloudUserData(t *testing.T) {
	raw := []byte("#cloud-config\nwrite_files: []\n")
	decoded, err := decodeAlibabaCloudUserData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("uncompressed user data changed")
	}

	decoded, err = decodeAlibabaCloudUserData(gzipData(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("compressed user data did not round-trip")
	}
}

func TestDecodeAlibabaCloudUserDataLimit(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{name: "raw exact limit", data: bytes.Repeat([]byte{'x'}, maxAlibabaCloudUserDataSize), ok: true},
		{name: "raw over limit", data: bytes.Repeat([]byte{'x'}, maxAlibabaCloudUserDataSize+1)},
		{name: "gzip exact limit", data: gzipData(t, bytes.Repeat([]byte{'x'}, maxAlibabaCloudUserDataSize)), ok: true},
		{name: "gzip decompressed over limit", data: gzipData(t, bytes.Repeat([]byte{'x'}, maxAlibabaCloudUserDataSize+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeAlibabaCloudUserData(test.data)
			if test.ok {
				require.NoError(t, err)
				require.Len(t, decoded, maxAlibabaCloudUserDataSize)
				return
			}
			require.Error(t, err)
		})
	}
}
