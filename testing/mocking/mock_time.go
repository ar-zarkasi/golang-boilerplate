package mocking

import "time"

type MockTimeProvider struct {
	now time.Time
}

func (m *MockTimeProvider) Now() time.Time {
	return m.now
}