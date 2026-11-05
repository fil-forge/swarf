package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStreamCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/revocations/after/0", request.URL.Path)
		require.Equal(t, "text/event-stream", request.Header.Get("Accept"))
		_, _ = fmt.Fprint(writer, "event: ignored\ndata: ignored\n\nevent: revocation\ndata: {\"revoke\":\"one\"}\n\nevent: revocation\ndata: {\"revoke\":\"two\"}\n\n")
	}))
	defer server.Close()

	command := newStreamCommand()
	output := bytes.NewBuffer(nil)
	command.SetOut(output)
	command.SetArgs([]string{"--service-url", server.URL, "--after", "0"})
	require.NoError(t, command.Execute())
	require.Equal(t, "{\"revoke\":\"one\"}\n{\"revoke\":\"two\"}\n", output.String())
}

// The service writes an error event when it cannot continue a stream, then
// closes. Ignoring it left the command exiting 0 on a service-side failure.
func TestStreamCommandReportsAnErrorEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = fmt.Fprint(writer, "event: revocation\ndata: {\"revoke\":\"one\"}\n\n")
		_, _ = fmt.Fprint(writer, "event: error\ndata: {\"error\":\"getting revocation: boom\"}\n\n")
	}))
	defer server.Close()

	command := newStreamCommand()
	output := bytes.NewBuffer(nil)
	command.SetOut(output)
	command.SetErr(bytes.NewBuffer(nil))
	command.SetArgs([]string{"--service-url", server.URL, "--after", "0"})

	err := command.Execute()
	require.ErrorContains(t, err, "getting revocation: boom")
	// Contains, not Equal: cobra writes the command's usage to the same
	// output for any error a RunE returns.
	require.Contains(t, output.String(), "{\"revoke\":\"one\"}\n",
		"records read before the error should still reach the output")
}

func TestStreamCommandRejectsInvalidAfter(t *testing.T) {
	for _, after := range []string{"", "later", "-1", "7-bafy", "2026-07-17T09:00:00Z", "18446744073709551616"} {
		requested := false
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requested = true
		}))
		command := newStreamCommand()
		command.SetOut(bytes.NewBuffer(nil))
		command.SetErr(bytes.NewBuffer(nil))
		command.SetArgs([]string{"--service-url", server.URL, "--after", after})
		require.ErrorContains(t, command.Execute(), "invalid --after", after)
		server.Close()
		require.False(t, requested, "an invalid --after %q reached the service", after)
	}
}

func TestStreamCommandAfterCursor(t *testing.T) {
	requestURL := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestURL <- request.URL.Path
	}))
	defer server.Close()

	command := newStreamCommand()
	command.SetArgs([]string{"--service-url", server.URL, "--after", "1734"})
	require.NoError(t, command.Execute())
	require.Equal(t, "/revocations/after/1734", requestURLValue(t, requestURL))
}

func TestStreamCommandReportsARefusedCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "cursor is ahead of the revocation stream", http.StatusConflict)
	}))
	defer server.Close()

	command := newStreamCommand()
	command.SetOut(bytes.NewBuffer(nil))
	command.SetErr(bytes.NewBuffer(nil))
	command.SetArgs([]string{"--service-url", server.URL, "--after", "1734"})
	require.ErrorContains(t, command.Execute(), "409")
}

func TestStreamCommandCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	command := newStreamCommand()
	command.SetArgs([]string{"--service-url", server.URL, "--after", "0"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- command.ExecuteContext(ctx)
	}()
	select {
	case <-requestStarted:
		cancel()
	case <-time.After(time.Second):
		require.Fail(t, "stream request was not opened")
	}
	require.NoError(t, <-result)
}

func TestStreamCommandDefaultsToNow(t *testing.T) {
	requestURL := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestURL <- request.URL.Path
	}))
	defer server.Close()

	command := newStreamCommand()
	command.SetArgs([]string{"--service-url", server.URL})
	require.NoError(t, command.Execute())
	require.Equal(t, "/revocations/after/now", requestURLValue(t, requestURL))
}

func requestURLValue(t *testing.T, values <-chan string) string {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		require.Fail(t, "stream request was not opened")
		return ""
	}
}
