package main

type Ruleset struct {
	Rules   map[string][]string `json:"rules"`
	Version int                 `json:"version"`
}
