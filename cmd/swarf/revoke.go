package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"syscall"

	"github.com/fil-forge/libforge/identity"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/spf13/cobra"
)

const (
	defaultServiceID  = "did:web:swarf.forgery.network"
	defaultServiceURL = "https://swarf.forgery.network"
)

func newRevokeCommand() *cobra.Command {
	var issuerKeyFile string
	var serviceID string
	var serviceURL string

	command := &cobra.Command{
		Use:   "revoke <revoke-cid> <delegation-or-container>",
		Short: "Publish a revocation",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuerKeyFile == "" {
				return errors.New("--issuer-key-file is required")
			}
			revoke, err := cid.Decode(args[0])
			if err != nil {
				return fmt.Errorf("decoding revoke CID: %w", err)
			}
			input, err := readInput(args[1])
			if err != nil {
				return err
			}
			witnesses, err := decodeDelegations(input)
			if err != nil {
				return err
			}
			key, err := os.ReadFile(issuerKeyFile)
			if err != nil {
				return fmt.Errorf("reading issuer key file: %w", err)
			}
			signer, err := identity.DecodeSignerFromPEM(key)
			if err != nil {
				return fmt.Errorf("decoding issuer key: %w", err)
			}
			issuer := multikey.KeyIssuer(signer)
			path, err := witnessPath(revoke, issuer.DID(), witnesses)
			if err != nil {
				return err
			}
			serviceDID, err := did.Parse(serviceID)
			if err != nil {
				return fmt.Errorf("parsing service DID: %w", err)
			}
			endpoint, err := url.Parse(serviceURL)
			if err != nil {
				return fmt.Errorf("parsing service URL: %w", err)
			}
			if !endpoint.IsAbs() || endpoint.Host == "" {
				return fmt.Errorf("service URL must be absolute: %q", serviceURL)
			}
			client, err := swarfclient.New(serviceDID, *endpoint)
			if err != nil {
				return fmt.Errorf("creating Swarf client: %w", err)
			}
			revoked := path[len(path)-1]
			if err := client.Publish(cmd.Context(), issuer, revoked, swarfclient.WithWitnessPath(path[:len(path)-1]...)); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "published revocation for %s\n", revoke)
			return err
		},
	}
	command.Flags().StringVar(&issuerKeyFile, "issuer-key-file", "", "path to the PEM-encoded Ed25519 issuer key")
	command.Flags().StringVar(&serviceID, "service-id", defaultServiceID, "Swarf service DID")
	command.Flags().StringVar(&serviceURL, "service-url", defaultServiceURL, "Swarf service URL")
	return command
}

// readInput returns the contents of value when it is a file path, and value
// itself otherwise.
func readInput(value string) ([]byte, error) {
	info, err := os.Stat(value)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENAMETOOLONG) {
			return []byte(value), nil
		}
		return nil, fmt.Errorf("stating delegation or container: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("delegation or container is a directory: %s", value)
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return nil, fmt.Errorf("reading delegation or container: %w", err)
	}
	return data, nil
}

// decodeDelegations decodes data as either a CBOR-encoded delegation or a UCAN
// container of delegations.
func decodeDelegations(data []byte) ([]ucan.Delegation, error) {
	if dlg, err := delegation.Decode(data); err == nil {
		return []ucan.Delegation{dlg}, nil
	}
	ct, err := container.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding input as UCAN container (and not a CBOR delegation): %w", err)
	}
	return ct.Delegations(), nil
}

func witnessPath(revoke cid.Cid, revoker did.DID, witnesses []ucan.Delegation) ([]ucan.Delegation, error) {
	delegations := make(map[cid.Cid]ucan.Delegation, len(witnesses))
	for _, delegation := range witnesses {
		delegations[delegation.Link()] = delegation
	}
	current, found := delegations[revoke]
	if !found {
		return nil, errors.New("input must include the revoked delegation")
	}
	if current.Issuer() == revoker {
		// Direct revocation: the revoker issued the revoked delegation, so no
		// witness path is needed to prove authority.
		return []ucan.Delegation{current}, nil
	}
	path := []ucan.Delegation{current}
	visited := map[cid.Cid]struct{}{current.Link(): {}}
	for {
		tail := path[len(path)-1]
		if tail.Issuer() == tail.Subject() {
			break
		}
		var parent ucan.Delegation
		for _, delegation := range witnesses {
			if delegation.Audience() != tail.Issuer() {
				continue
			}
			if parent != nil {
				return nil, fmt.Errorf("witness path has multiple parents for delegation %s", tail.Link())
			}
			parent = delegation
		}
		if parent == nil {
			return nil, fmt.Errorf("witness path has no parent for delegation %s", tail.Link())
		}
		if _, ok := visited[parent.Link()]; ok {
			return nil, fmt.Errorf("witness path contains a cycle at delegation %s", parent.Link())
		}
		visited[parent.Link()] = struct{}{}
		path = append(path, parent)
	}
	for i := len(path)/2 - 1; i >= 0; i-- {
		opposite := len(path) - 1 - i
		path[i], path[opposite] = path[opposite], path[i]
	}
	return path, nil
}
