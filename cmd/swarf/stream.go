package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newStreamCommand() *cobra.Command {
	var serviceURL string
	var since string
	command := &cobra.Command{
		Use:   "stream",
		Short: "Stream revocations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if since == "" {
				since = time.Now().UTC().Format(time.RFC3339Nano)
			}
			if err := validateSince(since); err != nil {
				return err
			}
			endpoint, err := url.Parse(serviceURL)
			if err != nil {
				return fmt.Errorf("parsing service URL: %w", err)
			}
			if !endpoint.IsAbs() || endpoint.Host == "" {
				return fmt.Errorf("service URL must be absolute: %q", serviceURL)
			}
			requestURL := strings.TrimRight(endpoint.String(), "/") + "/revocations/" + url.PathEscape(since)
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
	command.Flags().StringVar(&since, "since", "", "stream revocations created after this time: 0, RFC3339, or RFC3339Nano (default: now)")
	return command
}

func validateSince(value string) error {
	if value == "0" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("invalid since timestamp: %w", err)
	}
	return nil
}

func writeStreamEvents(cmd *cobra.Command, body io.Reader) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var event string
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if event == "revocation" && len(data) > 0 {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), strings.Join(data, "\n")); err != nil {
					return fmt.Errorf("writing revocation event: %w", err)
				}
			}
			event = ""
			data = nil
			continue
		}
		if value, ok := strings.CutPrefix(line, "event:"); ok {
			event = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading revocation stream: %w", err)
	}
	return nil
}
