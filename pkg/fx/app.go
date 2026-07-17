// Package fx wires the Swarf service application.
package fx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/swarf/pkg/build"
	"github.com/fil-forge/swarf/pkg/config"
	"github.com/fil-forge/swarf/pkg/store"
	memstore "github.com/fil-forge/swarf/pkg/store/memory"
	pgstore "github.com/fil-forge/swarf/pkg/store/postgres"
	"github.com/fil-forge/swarf/pkg/store/postgres/migrations"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func AppModule(cfg *config.Config) fx.Option {
	opts := []fx.Option{
		fx.Supply(cfg),
		fx.Provide(newLogger, newIdentity, newUCANServer, newEchoServer),
		fx.Invoke(registerServerLifecycle),
	}
	switch cfg.Storage.Type {
	case config.StorageTypeMemory:
		opts = append(opts, fx.Provide(fx.Annotate(memstore.New, fx.As(new(store.RevocationStore)))))
	case config.StorageTypePostgres, "":
		opts = append(opts, fx.Provide(newPostgresStore))
	default:
		return fx.Error(fmt.Errorf("unknown storage.type %q (valid: memory, postgres)", cfg.Storage.Type))
	}
	return fx.Options(opts...)
}

func newLogger(cfg *config.Config) (*zap.Logger, error) {
	zcfg := zap.NewProductionConfig()
	if err := zcfg.Level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		return nil, fmt.Errorf("parsing log level: %w", err)
	}
	return zcfg.Build()
}

func newIdentity(cfg *config.Config) (identity.Identity, error) {
	if cfg.Identity.KeyFile == "" {
		return identity.New("", cfg.Identity.ServiceID)
	}
	return identity.NewFromPEMFileWithDID(cfg.Identity.KeyFile, cfg.Identity.ServiceID)
}

func newPostgresStore(cfg *config.Config, lc fx.Lifecycle) (store.RevocationStore, error) {
	if cfg.Storage.Postgres.DSN == "" {
		return nil, errors.New("storage.postgres.dsn is required when storage.type is postgres")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.Storage.Postgres.DSN)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres DSN: %w", err)
	}
	if cfg.Storage.Postgres.MaxConns > 0 {
		poolCfg.MaxConns = cfg.Storage.Postgres.MaxConns
	}
	if cfg.Storage.Postgres.MinConns > 0 {
		poolCfg.MinConns = cfg.Storage.Postgres.MinConns
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating postgres pool: %w", err)
	}
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := pool.Ping(ctx); err != nil {
				return fmt.Errorf("pinging postgres: %w", err)
			}
			if !cfg.Storage.Postgres.SkipMigrations {
				if err := migrations.Up(ctx, pool, zap.NewNop()); err != nil {
					return fmt.Errorf("running postgres migrations: %w", err)
				}
			}
			return nil
		},
		OnStop: func(context.Context) error { pool.Close(); return nil },
	})
	return pgstore.New(pool), nil
}

func newUCANServer(id identity.Identity, cfg *config.Config, revocations store.RevocationStore) (*server.HTTPServer, error) {
	didResolver, err := newDIDResolver(id, cfg.Server.InsecureDIDResolution)
	if err != nil {
		return nil, err
	}
	srv := server.NewHTTP(id, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
	route := revokeRoute(revocations, didResolver)
	srv.Handle(route.Command, route.Handler)
	return srv, nil
}

func newDIDResolver(id identity.Identity, insecure bool) (resolver.ByMethod, error) {
	webOptions := []web.Option{}
	if insecure {
		webOptions = append(webOptions, web.WithInsecure(true))
	}
	webResolver, err := web.NewResolver(webOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating did:web resolver: %w", err)
	}
	document, err := id.DIDDocument()
	if err != nil {
		return nil, fmt.Errorf("creating DID document: %w", err)
	}
	return resolver.ByMethod{
		"key": key.Resolver,
		"web": resolver.Tiered{resolver.WellKnown{id.DID(): document}, webResolver},
	}, nil
}

func revokeRoute(revocations store.RevocationStore, didResolver resolver.ByMethod) server.Route {
	return ucancmd.Revoke.Route(func(req *binding.Request[*ucancmd.RevokeArguments], res *binding.Response[*ucancmd.RevokeOK]) error {
		args := req.Task().Arguments()
		witnesses := make(map[cid.Cid]ucan.Delegation)
		for _, delegation := range req.Metadata().Delegations() {
			witnesses[delegation.Link()] = delegation
		}
		path := make([]ucan.Delegation, len(args.Path))
		for i, link := range args.Path {
			delegation, ok := witnesses[link]
			if !ok {
				return fmt.Errorf("delegation %s at path index %d is not in request metadata", link, i)
			}
			path[i] = delegation
		}
		if len(path) == 0 || path[len(path)-1].Link() != args.Revoke {
			return errors.New("revocation path must end with the revoked delegation")
		}
		if err := validateRevocationPath(req.Context(), path, didResolver); err != nil {
			return fmt.Errorf("validating revocation path: %w", err)
		}
		// TODO: support delegated revocations, where the revocation issuer is not
		// the same as the invocation issuer.
		// See https://github.com/ucan-wg/revocation#delegating-revocation
		issuerFound := false
		for _, delegation := range path {
			if delegation.Issuer() == req.Invocation().Issuer() {
				issuerFound = true
				break
			}
		}
		if !issuerFound {
			return errors.New("revocation issuer is not an issuer in the delegation path")
		}
		if err := revocations.Add(req.Context(), req.Invocation(), path); err != nil {
			return fmt.Errorf("adding revocation: %w", err)
		}
		return res.SetSuccess(&ucancmd.RevokeOK{})
	})
}

func validateRevocationPath(ctx context.Context, path []ucan.Delegation, didResolver resolver.ByMethod) error {
	if len(path) == 0 {
		return errors.New("revocation path must not be empty")
	}
	rootSubject := path[0].Subject()
	if rootSubject != path[0].Issuer() {
		return errors.New("root delegation subject must equal its issuer")
	}
	for i, delegation := range path {
		if err := validator.ValidateToken(ctx, delegation, validator.WithDIDResolver(didResolver)); err != nil {
			return fmt.Errorf("validating delegation at path index %d: %w", i, err)
		}
		if i == 0 {
			continue
		}
		if delegation.Subject() != rootSubject && delegation.Subject() != did.Undef {
			return fmt.Errorf("delegation at path index %d has a different subject", i)
		}
		if delegation.Issuer() != path[i-1].Audience() {
			return fmt.Errorf("delegation at path index %d issuer does not match the previous audience", i)
		}
	}
	return nil
}

func newEchoServer(id identity.Identity, ucanServer *server.HTTPServer, revocations store.RevocationStore) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.GET("/", serverInfoHandler(id))
	e.GET("/.well-known/did.json", didDocumentHandler(id))
	e.GET("/revocation/:cid", revocationHandler(revocations))
	e.GET("/revocations/:since", firehoseHandler(revocations))
	e.POST("/", echo.WrapHandler(ucanServer))
	return e
}

type serverInfo struct {
	ID    string    `json:"id"`
	Build buildInfo `json:"build"`
}

type buildInfo struct {
	Version string `json:"version"`
	Repo    string `json:"repo"`
}

func serverInfoHandler(id identity.Identity) echo.HandlerFunc {
	info := serverInfo{
		ID: id.DID().String(),
		Build: buildInfo{
			Version: build.Version,
			Repo:    "https://github.com/fil-forge/swarf",
		},
	}
	return func(c echo.Context) error {
		if strings.Contains(strings.ToLower(c.Request().Header.Get("Accept")), "application/json") {
			return c.JSON(http.StatusOK, info)
		}
		return c.String(http.StatusOK, fmt.Sprintf("😶 swarf %s\n- %s\n- %s", info.Build.Version, info.Build.Repo, info.ID))
	}
}

func didDocumentHandler(id identity.Identity) echo.HandlerFunc {
	return func(c echo.Context) error {
		document, err := id.DIDDocument()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "building DID document")
		}
		return c.JSON(http.StatusOK, document)
	}
}

func firehoseHandler(revocations store.RevocationStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		since, err := parseSince(c.Param("since"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		response := c.Response()
		response.Header().Set(echo.HeaderContentType, "text/event-stream")
		response.Header().Set(echo.HeaderCacheControl, "no-cache")
		response.Header().Set(echo.HeaderConnection, "keep-alive")
		response.WriteHeader(http.StatusOK)

		for record, err := range revocations.Stream(c.Request().Context(), since) {
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				writeFirehoseError(response, err)
				return nil
			}
			if err := writeFirehoseRecord(response, record); err != nil {
				return err
			}
		}
		return nil
	}
}

func revocationHandler(revocations store.RevocationStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		delegation, err := cid.Decode(c.Param("cid"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid delegation CID")
		}
		record, err := revocations.Get(c.Request().Context(), delegation)
		if errors.Is(err, store.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "revocation not found")
		}
		if err != nil {
			return fmt.Errorf("getting revocation: %w", err)
		}
		data, err := encodeRevocationRecord(record)
		if err != nil {
			return fmt.Errorf("encoding revocation: %w", err)
		}
		return c.Blob(http.StatusOK, "application/vnd.ipld.dag-json", data)
	}
}

func parseSince(value string) (time.Time, error) {
	if value == "0" {
		return time.Time{}, nil
	}
	since, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid since timestamp: %w", err)
	}
	return since, nil
}

func writeFirehoseRecord(response *echo.Response, record store.RevocationRecord) error {
	path := make([]cid.Cid, len(record.Path))
	for i, delegation := range record.Path {
		path[i] = delegation.Link()
	}
	data, err := encodeFirehoseEvent(api.FirehoseRevocation{
		Revoke:    record.Revoke,
		Path:      path,
		Cause:     record.Cause.Link(),
		CreatedAt: jsg.DagJsonTime(record.CreatedAt),
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(response, "id: %s\nevent: revocation\ndata: %s\n\n", record.Cause.Link(), data); err != nil {
		return fmt.Errorf("writing revocation event: %w", err)
	}
	response.Flush()
	return nil
}

func encodeRevocationRecord(record store.RevocationRecord) ([]byte, error) {
	cause, err := invocation.Encode(record.Cause)
	if err != nil {
		return nil, fmt.Errorf("encoding revocation cause: %w", err)
	}
	path := make([][]byte, len(record.Path))
	for i, dlg := range record.Path {
		path[i], err = delegation.Encode(dlg)
		if err != nil {
			return nil, fmt.Errorf("encoding delegation at path index %d: %w", i, err)
		}
	}
	value := api.Revocation{
		Revoke:    record.Revoke,
		Cause:     cause,
		Path:      path,
		CreatedAt: jsg.DagJsonTime(record.CreatedAt),
	}
	var data bytes.Buffer
	err = value.MarshalDagJSON(&data)
	if err != nil {
		return nil, fmt.Errorf("encoding revocation record as DAG-JSON: %w", err)
	}
	return data.Bytes(), nil
}

func encodeFirehoseEvent(event api.FirehoseRevocation) ([]byte, error) {
	var data bytes.Buffer
	if err := event.MarshalDagJSON(&data); err != nil {
		return nil, fmt.Errorf("encoding firehose record as DAG-JSON: %w", err)
	}
	return data.Bytes(), nil
}

func writeFirehoseError(response *echo.Response, err error) {
	data, marshalErr := json.Marshal(map[string]string{"error": err.Error()})
	if marshalErr != nil {
		return
	}
	_, _ = fmt.Fprintf(response, "event: error\ndata: %s\n\n", data)
	response.Flush()
}

func registerServerLifecycle(lc fx.Lifecycle, e *echo.Echo, cfg *config.Config) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			address := net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port))
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return fmt.Errorf("binding %s: %w", address, err)
			}
			e.Listener = listener
			go func() { _ = e.Start(address) }()
			return nil
		},
		OnStop: func(ctx context.Context) error { return e.Shutdown(ctx) },
	})
}
