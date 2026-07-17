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
		require.Equal(t, "/revocations/0", request.URL.Path)
		require.Equal(t, "text/event-stream", request.Header.Get("Accept"))
		_, _ = fmt.Fprint(writer, "event: ignored\ndata: ignored\n\nevent: revocation\ndata: {\"revoke\":\"one\"}\n\nevent: revocation\ndata: {\"revoke\":\"two\"}\n\n")
	}))
	defer server.Close()

	command := newStreamCommand()
	output := bytes.NewBuffer(nil)
	command.SetOut(output)
	command.SetArgs([]string{"--service-url", server.URL, "0"})
	require.NoError(t, command.Execute())
	require.Equal(t, "{\"revoke\":\"one\"}\n{\"revoke\":\"two\"}\n", output.String())
}

func TestStreamCommandRejectsInvalidSince(t *testing.T) {
	command := newStreamCommand()
	command.SetArgs([]string{"not-a-timestamp"})
	require.Error(t, command.Execute())
}

func TestStreamCommandCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	command := newStreamCommand()
	command.SetArgs([]string{"--service-url", server.URL, "0"})
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
