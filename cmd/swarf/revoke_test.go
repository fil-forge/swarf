package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
)

func TestWitnessPath(t *testing.T) {
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	root, err := delegation.Delegate(alice, bob.DID(), alice.DID(), command)
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, carol.DID(), alice.DID(), command)
	require.NoError(t, err)

	path, err := witnessPath(target.Link(), carol.DID(), []ucan.Delegation{target, root})
	require.NoError(t, err)
	require.Equal(t, []ucan.Delegation{root, target}, path)

	// bob issued target, so no witness path is needed beyond the delegation.
	path, err = witnessPath(target.Link(), bob.DID(), []ucan.Delegation{target})
	require.NoError(t, err)
	require.Equal(t, []ucan.Delegation{target}, path)

	_, err = witnessPath(target.Link(), carol.DID(), []ucan.Delegation{root})
	require.Error(t, err)
}

func TestReadInput(t *testing.T) {
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	delegation, err := delegation.Delegate(alice, did.Undef, alice.DID(), command)
	require.NoError(t, err)
	encoded, err := container.Encode(container.Base64url, container.New(container.WithDelegations(delegation)))
	require.NoError(t, err)

	inline, err := readInput(string(encoded))
	require.NoError(t, err)
	require.Equal(t, encoded, inline)

	path := filepath.Join(t.TempDir(), "witness.container")
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	fromFile, err := readInput(path)
	require.NoError(t, err)
	require.Equal(t, encoded, fromFile)
}

func TestDecodeDelegations(t *testing.T) {
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	root, err := delegation.Delegate(alice, bob.DID(), alice.DID(), command)
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, did.Undef, alice.DID(), command)
	require.NoError(t, err)

	// A bare CBOR-encoded delegation decodes to itself.
	encoded, err := delegation.Encode(target)
	require.NoError(t, err)
	decoded, err := decodeDelegations(encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Equal(t, target.Link(), decoded[0].Link())

	// A UCAN container decodes to its delegations.
	encoded, err = container.Encode(container.Base64url, container.New(container.WithDelegations(root, target)))
	require.NoError(t, err)
	decoded, err = decodeDelegations(encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 2)

	_, err = decodeDelegations([]byte("not a delegation or container"))
	require.Error(t, err)
}

func TestRevokeCommandDefaults(t *testing.T) {
	command := newRevokeCommand()
	serviceID, err := command.Flags().GetString("service-id")
	require.NoError(t, err)
	require.Equal(t, defaultServiceID, serviceID)
	serviceURL, err := command.Flags().GetString("service-url")
	require.NoError(t, err)
	require.Equal(t, defaultServiceURL, serviceURL)
}
