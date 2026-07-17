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
		Use:   "revoke <revoke-cid> <witness-path-container>",
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
			containerBytes, err := readContainer(args[1])
			if err != nil {
				return err
			}
			witnesses, err := container.Decode(containerBytes)
			if err != nil {
				return fmt.Errorf("decoding witness path container: %w", err)
			}
			path, err := witnessPath(revoke, witnesses.Delegations())
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
			client, err := swarfclient.New(serviceDID, *endpoint, issuer)
			if err != nil {
				return fmt.Errorf("creating Swarf client: %w", err)
			}
			if err := client.Publish(cmd.Context(), revoke, path); err != nil {
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

func readContainer(value string) ([]byte, error) {
	info, err := os.Stat(value)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENAMETOOLONG) {
			return []byte(value), nil
		}
		return nil, fmt.Errorf("stating witness path container: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("witness path container is a directory: %s", value)
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return nil, fmt.Errorf("reading witness path container: %w", err)
	}
	return data, nil
}

func witnessPath(revoke cid.Cid, witnesses []ucan.Delegation) ([]ucan.Delegation, error) {
	delegations := make(map[cid.Cid]ucan.Delegation, len(witnesses))
	for _, delegation := range witnesses {
		delegations[delegation.Link()] = delegation
	}
	current, found := delegations[revoke]
	if !found {
		return nil, errors.New("witness path container must include the revoked delegation")
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
