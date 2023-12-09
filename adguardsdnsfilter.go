package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/samber/lo"
)

const AdGuardSDNSFilter = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"

func adguard(ctx context.Context, c *http.Client) (hasReg *Ruleset, noReg *Ruleset, err error) {
	b, err := getFilter(ctx, c)
	if err != nil {
		return nil, nil, fmt.Errorf("adguard: %w", err)
	}
	domain := map[string]struct{}{}
	domainRegex := map[string]struct{}{}
	domainSuffix := map[string]struct{}{}

	s := filterlist.NewRuleScanner(bytes.NewReader(b), 1, true)

	for s.Scan() {
		r, _ := s.Rule()
		hr, ok := r.(*rules.NetworkRule)
		if !ok || !hr.IsHostLevelNetworkRule() || hr.Whitelist {
			continue
		}
		if hr.IsRegexRule() {
			continue
		}

		rule := strings.TrimSuffix(strings.TrimLeft(hr.RuleText, "|"), "^")

		if rule == hr.Shortcut {
			rule = strings.TrimPrefix(rule, "://")
			if strings.HasPrefix(rule, ".") {
				domainSuffix[rule] = struct{}{}
				continue
			}
			if strings.HasSuffix(rule, ".") {
				domainRegex[`^(.*\.)?`+rule] = struct{}{}
				continue
			}
			domain[rule] = struct{}{}
			continue
		}
		ruleR := strings.TrimPrefix(rule, "://")
		ruleR = strings.ReplaceAll(ruleR, ".", `\.`)
		reg := strings.ReplaceAll(ruleR, "*", ".*")
		if !strings.HasPrefix(hr.RuleText, "*") {
			reg = `^(.*\.)?` + reg
		}
		if strings.HasSuffix(hr.RuleText, "^") {
			reg = reg + "$"
		}
		domainRegex[reg] = struct{}{}
	}
	for k := range domain {
		domainSuffix["."+k] = struct{}{}
	}

	rules := []map[string][]any{
		{
			"domain":        toAny(domain),
			"domain_suffix": toAny(domainSuffix),
			"domain_regex":  toAny(domainRegex),
		},
	}
	noRegRules := maps.Clone(rules[0])
	delete(noRegRules, "domain_regex")

	return NewRuleSet(rules), NewRuleSet([]map[string][]any{noRegRules}), nil
}

func toAny(m map[string]struct{}) []any {
	sl := lo.Keys(m)
	slices.Sort(sl)
	return lo.Map[string, any](sl, func(item string, index int) any { return item })
}

func getFilter(ctx context.Context, c *http.Client) ([]byte, error) {
	reps, err := http.NewRequestWithContext(ctx, "GET", AdGuardSDNSFilter, nil)
	if err != nil {
		return nil, fmt.Errorf("getFilter: %w", err)
	}
	rep, err := c.Do(reps)
	if err != nil {
		return nil, fmt.Errorf("getFilter: %w", err)
	}
	defer rep.Body.Close()

	b, err := io.ReadAll(rep.Body)
	if err != nil {
		return nil, fmt.Errorf("getFilter: %w", err)
	}
	return b, nil
}
