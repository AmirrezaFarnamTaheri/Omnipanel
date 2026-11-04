package enrollment

import "database/sql"

// ApprovedSQLStore is a reserved admission adapter. It is currently a
// passthrough stub, so new approval-revocation regression tests MUST fail.
type ApprovedSQLStore struct {
	*SQLStore
}

func NewApprovedSQLStore(db *sql.DB) (*ApprovedSQLStore, error) {
	base, err := NewSQLStore(db)
	if err != nil {
		return nil, err
	}
	return &ApprovedSQLStore{SQLStore: base}, nil
}
