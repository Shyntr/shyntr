package usecase

import (
	"testing"
	"time"
)

// These tests pin the injectable-clock contract for samlBuilderUseCase: a nil
// clock (production default) yields wall-clock time, an injected clock yields
// exactly its value, and a zero-value struct must not panic.

func TestSamlBuilderNow_ZeroValueDoesNotPanic(t *testing.T) {
	s := &samlBuilderUseCase{} // clock field is nil

	before := time.Now()
	got := s.now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Fatalf("zero-value now() = %v, want within [%v, %v]", got, before, after)
	}
}

func TestNewSamlBuilderUseCaseWithClock_NilClockUsesWallClock(t *testing.T) {
	uc := NewSamlBuilderUseCaseWithClock(nil, nil, nil, nil, nil, nil, nil)
	s := uc.(*samlBuilderUseCase)

	before := time.Now()
	got := s.now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Fatalf("nil-clock now() = %v, want within [%v, %v]", got, before, after)
	}
}

func TestNewSamlBuilderUseCaseWithClock_FixedClock(t *testing.T) {
	fixed := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	uc := NewSamlBuilderUseCaseWithClock(nil, nil, nil, nil, nil, nil, func() time.Time { return fixed })
	s := uc.(*samlBuilderUseCase)

	if got := s.now(); !got.Equal(fixed) {
		t.Fatalf("fixed-clock now() = %v, want %v", got, fixed)
	}
}
