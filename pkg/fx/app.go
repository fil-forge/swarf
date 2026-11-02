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
	"net/url"
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
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"

	// Registers the secp256k1 verifier decoder: did:plc issuers carry
	// secp256k1 verification methods.
	_ "github.com/fil-forge/ucantone/multikey/secp256k1/verifier"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

func newUCANServer(id identity.Identity, cfg *config.Config, revocations store.RevocationStore, logger *zap.Logger) (*server.HTTPServer, error) {
	didResolver, err := newDIDResolver(id, cfg.Server.InsecureDIDResolution, cfg.PLC.Directory)
	if err != nil {
		return nil, err
	}
	srv := server.NewHTTP(id, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
	for _, route := range revokeRoutes(revocations, didResolver, logger) {
		srv.Handle(route.Command, route.Handler)
	}
	return srv, nil
}

func newDIDResolver(id identity.Identity, insecure bool, plcDirectory string) (resolver.ByMethod, error) {
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
	if plcDirectory == "" {
		plcDirectory = config.DefaultPLCDirectory
	}
	plcURL, err := url.Parse(plcDirectory)
	if err != nil {
		return nil, fmt.Errorf("parsing PLC directory URL %q: %w", plcDirectory, err)
	}
	plcResolver, err := plc.NewResolver(*plcURL)
	if err != nil {
		return nil, fmt.Errorf("creating did:plc resolver: %w", err)
	}
	return resolver.ByMethod{
		"key": key.Resolver,
		"web": resolver.Tiered{resolver.WellKnown{id.DID(): document}, webResolver},
		"plc": resolver.NewCached(plcResolver, time.Hour*3),
	}, nil
}

func revokeRoutes(revocations store.RevocationStore, didResolver resolver.ByMethod, logger *zap.Logger) []server.Route {
	return []server.Route{revokeRoute(revocations, didResolver), revokeBatchRoute(revocations, didResolver, logger)}
}

func revokeRoute(revocations store.RevocationStore, didResolver resolver.ByMethod) server.Route {
	return ucancmd.Revoke.Route(func(req *binding.Request[*ucancmd.RevokeArguments], res *binding.Response[*ucancmd.RevokeOK]) error {
		witnesses := indexDelegations(req.Metadata().Delegations())
		path, err := getRevocationPath(req.Context(), req.Invocation().Issuer(), *req.Task().Arguments(), witnesses, didResolver)
		if err != nil {
			return err
		}
		if err := revocations.Add(req.Context(), req.Invocation(), [][]ucan.Delegation{path}); err != nil {
			return fmt.Errorf("adding revocation: %w", err)
		}
		return res.SetSuccess(&ucancmd.RevokeOK{})
	})
}

// revokeBatchRoute validates every revocation of the batch and stores them
// with one write. One invalid revocation rejects the whole batch.
func revokeBatchRoute(revocations store.RevocationStore, didResolver resolver.ByMethod, logger *zap.Logger) server.Route {
	return ucancmd.RevokeBatch.Route(func(req *binding.Request[*ucancmd.RevokeBatchArguments], res *binding.Response[*ucancmd.RevokeBatchOK]) error {
		args := req.Task().Arguments()
		if len(args.Revocations) == 0 {
			return errors.New("the batch must contain at least one revocation")
		}
		log := logger.With(
			zap.Stringer("issuer", req.Invocation().Issuer()),
			zap.Stringer("invocation", req.Invocation().Link()),
			zap.Int("count", len(args.Revocations)),
		)
		witnesses := indexDelegations(req.Metadata().Delegations())
		paths := make([][]ucan.Delegation, len(args.Revocations))
		for i, revocation := range args.Revocations {
			path, err := getRevocationPath(req.Context(), req.Invocation().Issuer(), revocation, witnesses, didResolver)
			if err != nil {
				err = fmt.Errorf("revocation %d of %s: %w", i, revocation.Revoke, err)
				log.Warn("rejected revocation batch", zap.Error(err))
				return err
			}
			paths[i] = path
		}
		start := time.Now()
		err := revocations.Add(req.Context(), req.Invocation(), paths)
		log = log.With(zap.Duration("duration", time.Since(start)))
		if err != nil {
			log.Error("storing revocation batch failed", zap.Error(err))
			return fmt.Errorf("adding revocations: %w", err)
		}
		log.Info("stored revocation batch")
		return res.SetSuccess(&ucancmd.RevokeBatchOK{})
	})
}

func indexDelegations(delegations []ucan.Delegation) map[cid.Cid]ucan.Delegation {
	index := make(map[cid.Cid]ucan.Delegation, len(delegations))
	for _, delegation := range delegations {
		index[delegation.Link()] = delegation
	}
	return index
}

// getRevocationPath checks that issuer may revoke args.Revoke and returns the
// delegation path from the root delegation to the revoked one. The revoked
// delegation and every delegation of the path must be among witnesses.
func getRevocationPath(ctx context.Context, issuer did.DID, args ucancmd.RevokeArguments, witnesses map[cid.Cid]ucan.Delegation, didResolver resolver.ByMethod) ([]ucan.Delegation, error) {
	revoked, ok := witnesses[args.Revoke]
	if !ok {
		return nil, errors.New("the revoked delegation must be included in request metadata")
	}
	if len(args.Path) == 0 {
		// Direct revocation: the issuer of the revoked delegation revokes it
		// themselves. A witness path is only needed to prove authority over a
		// delegation issued by someone else further down a chain the revoker
		// is involved in.
		if revoked.Issuer() != issuer {
			return nil, errors.New("witness path required: revocation issuer did not issue the revoked delegation")
		}
		if err := validator.ValidateToken(ctx, revoked, validator.WithDIDResolver(didResolver)); err != nil {
			return nil, fmt.Errorf("validating revoked delegation: %w", err)
		}
		return []ucan.Delegation{revoked}, nil
	}
	path := make([]ucan.Delegation, len(args.Path))
	for i, link := range args.Path {
		delegation, ok := witnesses[link]
		if !ok {
			return nil, fmt.Errorf("delegation %s at path index %d is not in request metadata", link, i)
		}
		path[i] = delegation
	}
	if path[len(path)-1].Link() != args.Revoke {
		return nil, errors.New("revocation path must end with the revoked delegation")
	}
	if err := validateRevocationPath(ctx, path, didResolver); err != nil {
		return nil, fmt.Errorf("validating revocation path: %w", err)
	}
	// TODO: support delegated revocations, where the revocation issuer is not
	// the same as the invocation issuer.
	// See https://github.com/ucan-wg/revocation#delegating-revocation
	for _, delegation := range path {
		if delegation.Issuer() == issuer {
			return path, nil
		}
	}
	return nil, errors.New("revocation issuer is not an issuer in the delegation path")
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
	// Outermost middleware: a handler panic becomes a 500 rather than a
	// dropped connection.
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.POST, echo.OPTIONS},
		MaxAge:       86400,
	}))
	e.GET("/", serverInfoHandler(id))
	e.GET("/health", healthHandler)
	e.GET("/.well-known/did.json", didDocumentHandler(id))
	e.GET("/revocation/:cid", revocationHandler(revocations))
	e.GET("/revocations/:from", firehoseHandler(revocations))
	e.POST("/", echo.WrapHandler(ucanServer))
	return e
}

// healthHandler returns health status.
func healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "healthy",
	})
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
		from, err := parseFrom(c.Param("from"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		response := c.Response()
		response.Header().Set(echo.HeaderContentType, "text/event-stream")
		response.Header().Set(echo.HeaderCacheControl, "no-cache")
		response.Header().Set(echo.HeaderConnection, "keep-alive")
		response.WriteHeader(http.StatusOK)

		for record, err := range revocations.Stream(c.Request().Context(), from) {
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				writeFirehoseError(response, err)
				// The response committed 200 before the stream began, so the
				// status cannot carry this. Returning the error is the only
				// thing an error handler or request logger ever sees; on nil
				// a failed stream is indistinguishable from a clean one.
				return fmt.Errorf("streaming revocations: %w", err)
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
		c.Response().Header().Set(echo.HeaderCacheControl, "public, max-age=31536000, immutable")
		return c.Blob(http.StatusOK, "application/vnd.ipld.dag-json", data)
	}
}

func parseFrom(value string) (time.Time, error) {
	if value == "0" {
		return time.Time{}, nil
	}
	from, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid from timestamp: %w", err)
	}
	return from, nil
}

func writeFirehoseRecord(response *echo.Response, record store.RevocationRecord) error {
	path := make([]cid.Cid, len(record.Path))
	for i, delegation := range record.Path {
		path[i] = delegation.Link()
	}
	data, err := encodeFirehoseEvent(api.FirehoseRevocation{
		Revoke:     record.Revoke,
		Path:       path,
		Cause:      record.Cause.Link(),
		RecordedAt: jsg.DagJsonTime(record.RecordedAt),
	})
	if err != nil {
		return err
	}
	// One invocation can revoke several delegations, so the event id names
	// both the cause and the revoked delegation.
	if _, err := fmt.Fprintf(response, "id: %s/%s\nevent: revocation\ndata: %s\n\n", record.Cause.Link(), record.Revoke, data); err != nil {
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
		Revoke:     record.Revoke,
		Cause:      cause,
		Path:       path,
		RecordedAt: jsg.DagJsonTime(record.RecordedAt),
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
