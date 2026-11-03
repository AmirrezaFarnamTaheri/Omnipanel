// Database-backed modules only need a parseable URL for these pure unit tests.
// No connection is opened; integration tests provide their own PostgreSQL service.
process.env.DATABASE_URL ??= "postgres://test:test@127.0.0.1:5432/omnipanel_test";
