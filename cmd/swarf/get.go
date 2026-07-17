package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/spf13/cobra"
)

func newGetCommand() *cobra.Command {
	var serviceURL string
	command := &cobra.Command{
		Use:   "get <revoke-cid>",
		Short: "Retrieve a revocation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			revoke, err := cid.Decode(args[0])
			if err != nil {
				return fmt.Errorf("decoding revoke CID: %w", err)
			}
			endpoint, err := url.Parse(serviceURL)
			if err != nil {
				return fmt.Errorf("parsing service URL: %w", err)
			}
			if !endpoint.IsAbs() || endpoint.Host == "" {
				return fmt.Errorf("service URL must be absolute: %q", serviceURL)
			}
			requestURL := strings.TrimRight(endpoint.String(), "/") + "/revocation/" + url.PathEscape(revoke.String())
			request, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
			if err != nil {
				return fmt.Errorf("creating revocation request: %w", err)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return fmt.Errorf("getting revocation: %w", err)
			}
			defer response.Body.Close()
			if response.StatusCode == http.StatusNotFound {
				return nil
			}
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("getting revocation: unexpected status %s", response.Status)
			}
			_, err = io.Copy(cmd.OutOrStdout(), response.Body)
			return err
		},
	}
	command.Flags().StringVar(&serviceURL, "service-url", defaultServiceURL, "Swarf service URL")
	return command
}
