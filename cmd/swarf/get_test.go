package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestGetCommand(t *testing.T) {
	revoke := mustCID(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/revocation/"+revoke.String(), request.URL.Path)
		_, _ = writer.Write([]byte(`{"revoke":{"/":"` + revoke.String() + `"}}`))
	}))
	defer server.Close()

	command := newGetCommand()
	output := bytes.NewBuffer(nil)
	command.SetOut(output)
	command.SetArgs([]string{"--service-url", server.URL, revoke.String()})
	require.NoError(t, command.Execute())
	require.Equal(t, `{"revoke":{"/":"`+revoke.String()+`"}}`, output.String())
}

func TestGetCommandDoesNotPrintNotFound(t *testing.T) {
	revoke := mustCID(t)
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	command := newGetCommand()
	output := bytes.NewBuffer(nil)
	command.SetOut(output)
	command.SetArgs([]string{"--service-url", server.URL, revoke.String()})
	require.NoError(t, command.Execute())
	require.Empty(t, output.String())
}

func mustCID(t *testing.T) cid.Cid {
	t.Helper()
	value, err := cid.Decode("bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4")
	require.NoError(t, err)
	return value
}
