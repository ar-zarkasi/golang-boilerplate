package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// FilterQuery represents a filter condition for database queries
// @Description Filter query object for filtering data
type FilterQuery struct {
	Column     string   `json:"column" example:"name"`                           // Column name to filter on
	Operand    string   `json:"operand" example:"like" enums:"=,!=,>,<,>=,<=,like,in,not_in,is_null,is_not_null"` // Operator for the filter
	Value      *string  `json:"value" example:"admin"`                           // Single value for the filter (used with =, !=, >, <, >=, <=, like)
	ValueArray []string `json:"value_array" example:"admin,user"`                // Array of values (used with in, not_in)
}

type SORTING string

const (
	SORTING_ASC  SORTING = "asc"
	SORTING_DESC SORTING = "desc"
)

type JSONB map[string]interface{}

// Value implements the driver.Valuer interface for JSONB
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface for JSONB
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("failed to scan JSONB value")
	}

	return json.Unmarshal(bytes, j)
}

type ResponseDefault struct {
	Status  bool   `json:"status"`
	Code    int    `json:"code"`
	Data    any    `json:"data"`
	Message string `json:"message"`
}
