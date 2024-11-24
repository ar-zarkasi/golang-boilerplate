package utils

import (
	"os"
	"time"
)

type TimeProvider interface {
	Now() time.Time
	IntDateToString(date int) string
	FormattedDate(date string, format string) string
}

type DefaultTimeProvider struct{}

func (d *DefaultTimeProvider) Now() time.Time {
	return time.Now()
}

func (d *DefaultTimeProvider) IntDateToString(date int) string {
	timezone := os.Getenv("TZ")
	dateString := time.Unix(int64(date), 0).In(time.FixedZone(timezone, 0))
	return dateString.Format(time.RFC3339)
}

func (d *DefaultTimeProvider) FormattedDate(date string, format string) string {
	dt, _ := time.Parse(time.RFC3339, date)
	return dt.Format(format)
}

