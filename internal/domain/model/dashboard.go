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

type AuthFailures struct {
	Range       string                          `json:"range"`
	GeneratedAt time.Time                       `json:"generated_at"`
	Totals      AuthFailureTotals               `json:"totals"`
	Reasons     []AuthFailureReason             `json:"reasons"`
	Protocols   map[string]AuthProtocolFailures `json:"protocols"`
}

type AuthFailureTotals struct {
	Failure int64 `json:"failure"`
}

type AuthFailureReason struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type AuthProtocolFailures struct {
	Failure   int64  `json:"failure"`
	TopReason string `json:"top_reason"`
}

type RoutingInsights struct {
	Range       string               `json:"range"`
	GeneratedAt time.Time            `json:"generated_at"`
	Transitions []ProtocolTransition `json:"transitions"`
	Totals      RoutingTotals        `json:"totals"`
}

type ProtocolTransition struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int64  `json:"count"`
}

type RoutingTotals struct {
	Routed       int64 `json:"routed"`
	SameProtocol int64 `json:"same_protocol"`
}

type HealthSummary struct {
	Status      string       `json:"status"`
	Checks      HealthChecks `json:"checks"`
	GeneratedAt time.Time    `json:"generated_at"`
}

type HealthChecks struct {
	Database    string `json:"database"`
	SigningKeys string `json:"signing_keys"`
	Migrations  string `json:"migrations"`
}
