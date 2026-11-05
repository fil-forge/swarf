package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/fil-forge/swarf/internal/sse"
	"github.com/spf13/cobra"
)

func newStreamCommand() *cobra.Command {
	var serviceURL string
	var after string
	command := &cobra.Command{
		Use:   "stream",
		Short: "Stream revocations",
		Long: `Stream revocations as they arrive, printing each as a DAG-JSON record.

By default the stream starts at the head of the revocation stream, so it
prints only the revocations that arrive from then on. Pass --after with a
cursor to start after that position instead, or --after 0 to stream every
revocation.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAfter(after); err != nil {
				return err
			}
			endpoint, err := url.Parse(serviceURL)
			if err != nil {
				return fmt.Errorf("parsing service URL: %w", err)
			}
			if !endpoint.IsAbs() || endpoint.Host == "" {
				return fmt.Errorf("service URL must be absolute: %q", serviceURL)
			}
			requestURL := strings.TrimRight(endpoint.String(), "/") + "/revocations/after/" + url.PathEscape(after)
			request, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
			if err != nil {
				return fmt.Errorf("creating revocation stream request: %w", err)
			}
			request.Header.Set("Accept", "text/event-stream")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				if cmd.Context().Err() != nil {
					return nil
				}
				return fmt.Errorf("opening revocation stream: %w", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("opening revocation stream: unexpected status %s", response.Status)
			}
			if err := writeStreamEvents(cmd, response.Body); err != nil {
				if cmd.Context().Err() != nil {
					return nil
				}
				return err
			}
			return nil
		},
	}
	command.Flags().StringVar(&serviceURL, "service-url", defaultServiceURL, "Swarf service URL")
	command.Flags().StringVar(&after, "after", "now", "stream revocations after this cursor, or after the head of the stream with now")
	return command
}

// validateAfter accepts a cursor, which is a decimal number, or now.
func validateAfter(value string) error {
	if value == "now" {
		return nil
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return fmt.Errorf("invalid --after %q: want a cursor or now", value)
	}
	return nil
}

func writeStreamEvents(cmd *cobra.Command, body io.Reader) error {
	events := sse.NewScanner(body)
	for events.Scan() {
		switch events.Event() {
		case "revocation":
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), events.Data()); err != nil {
				return fmt.Errorf("writing revocation event: %w", err)
			}
		case "error":
			// The service reports a stream it cannot continue as an error
			// event and then closes. Ignoring it ends the command at exit 0,
			// indistinguishable from reaching the end of the data.
			return fmt.Errorf("revocation stream: %s", events.Data())
		}
	}
	if err := events.Err(); err != nil {
		return fmt.Errorf("reading revocation stream: %w", err)
	}
	return nil
}
