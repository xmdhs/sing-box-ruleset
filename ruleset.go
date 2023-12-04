package main

type Ruleset struct {
	Rules   []map[string][]any `json:"rules"`
	Version int                `json:"version"`
}
