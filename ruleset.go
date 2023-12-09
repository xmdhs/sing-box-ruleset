package main

type Ruleset struct {
	Rules   []map[string][]any `json:"rules"`
	Version int                `json:"version"`
}

func NewRuleSet(rules []map[string][]any) *Ruleset {
	return &Ruleset{
		Rules:   rules,
		Version: 1,
	}
}
