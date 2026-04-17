package model

import "time"

type AuthActivity struct {
	Range       string                         `json:"range"`
	GeneratedAt time.Time                      `json:"generated_at"`
	Protocols   map[string]AuthActivityOutcome `json:"protocols"`
	Totals      AuthActivityOutcome            `json:"totals"`
}

type AuthActivityOutcome struct {
	Success int64 `json:"success"`
	Failure int64 `json:"failure"`
}
