package postgres

// WriteLockKey is writeLockKey, for the package's external tests to take the
// write lock as a writer does.
const WriteLockKey = writeLockKey

// WriteIdleTimeout is writeIdleTimeout, for the package's external tests to
// check the statement AddBatch sets it with.
const WriteIdleTimeout = writeIdleTimeout

// StreamPageSize is streamPageSize, for the package's external tests to
// store more rows than one page holds.
const StreamPageSize = streamPageSize
