package postgres

import (
	"fmt"
	"regexp"
	"strings"
)

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ValidateSchemaName accepts a plain lower-case identifier. The name goes into search_path,
// which is a list, so anything with a comma, a quote or a space must not get through.
func ValidateSchemaName(name string) error {
	if !schemaName.MatchString(name) {
		return fmt.Errorf("invalid schema name %q: want lower-case letters, digits and underscores, starting with a letter or underscore, at most 63 characters", name)
	}

	if strings.HasPrefix(name, "pg_") {
		return fmt.Errorf("invalid schema name %q: the pg_ prefix is reserved by PostgreSQL", name)
	}

	return nil
}
