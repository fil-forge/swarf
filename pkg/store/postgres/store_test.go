package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/swarf/pkg/store/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestScanRecord(t *testing.T) {
	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	path, err := delegation.Delegate(issuer, issuer.DID(), did.Undef, command)
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, command, nil)
	require.NoError(t, err)
	revocationBytes, err := invocation.Encode(revocation)
	require.NoError(t, err)
	pathBytes, err := delegation.Encode(path)
	require.NoError(t, err)
	createdAt := time.Now().UTC().Round(0)

	record, err := postgres.ScanRecord(recordRow{
		revocation:  revocationBytes,
		pathWitness: [][]byte{pathBytes},
		createdAt:   createdAt,
	})
	require.NoError(t, err)
	require.Equal(t, revocation.Link(), record.Revocation.Link())
	require.Len(t, record.Path, 1)
	require.Equal(t, path.Link(), record.Path[0].Link())
	require.Equal(t, createdAt, record.CreatedAt)
}

func TestScanRecordReturnsDecodeError(t *testing.T) {
	_, err := postgres.ScanRecord(recordRow{revocation: []byte("invalid")})
	require.Error(t, err)
}

func TestStreamCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, err := range (&postgres.Store{}).Stream(ctx, time.Time{}) {
		require.ErrorIs(t, err, context.Canceled)
		return
	}
	require.Fail(t, "Stream did not return context.Canceled")
}

type recordRow struct {
	revocation  []byte
	pathWitness [][]byte
	createdAt   time.Time
	err         error
}

func (r recordRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 3 {
		return errors.New("unexpected destination count")
	}
	*dest[0].(*[]byte) = r.revocation
	*dest[1].(*[][]byte) = r.pathWitness
	*dest[2].(*time.Time) = r.createdAt
	return nil
}
