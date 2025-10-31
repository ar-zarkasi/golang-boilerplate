package helpers

import (
	"app/src/constants"
	"os"
	"time"
)

type TimeProvider interface {
	Now() time.Time
	IntDateToString(date int) string
	FormattedDate(date string, format string) string
	IntToTime(date int) time.Time
	IntToDuration(date int) time.Duration
	StringToTime(date string, format string) time.Time
	DurationToInt(duration time.Duration) int
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

func (d *DefaultTimeProvider) IntToTime(date int) time.Time {
	return time.Unix(int64(date), 0)
}

func (d *DefaultTimeProvider) IntToDuration(date int) time.Duration {
	return time.Duration(date) * time.Second
}

func (d *DefaultTimeProvider) StringToTime(date string, format string) time.Time {
	dt, _ := time.Parse(format, date)
	return dt
}

func (d *DefaultTimeProvider) DateTimeToInt(date time.Time) int {
	return int(date.Unix())
}

func (d *DefaultTimeProvider) DateTimeToString(date time.Time) string {
	return date.Format(constants.FORMAT_DATETIME)
}

func (d *DefaultTimeProvider) StringToDateTime(date string) time.Time {
	dt, _ := time.Parse(constants.FORMAT_DATETIME, date)
	return dt
}

func (d *DefaultTimeProvider) DurationToInt(duration time.Duration) int {
	return int(duration.Seconds())
}
