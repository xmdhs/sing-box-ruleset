package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/samber/lo"
)

const AdGuardSDNSFilter = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"

func adguard(ctx context.Context, c *http.Client) (*Ruleset, error) {
	b, err := getFilter(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("adguard: %w", err)
	}
	domain := map[string]struct{}{}
	domainRegex := map[string]struct{}{}
	domainSuffix := map[string]struct{}{}
	domainKeyword := map[string]struct{}{}

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
				domainKeyword[rule] = struct{}{}
				continue
			}
			domain[rule] = struct{}{}
			continue
		}
		if strings.HasPrefix(rule, "*") || strings.HasSuffix(rule, "*") {
			domainKeyword[strings.ReplaceAll(rule, "*", "")] = struct{}{}
			continue
		}
		ruleR := strings.TrimPrefix(rule, "://")
		ruleR = strings.ReplaceAll(ruleR, ".", `\.`)
		reg := strings.ReplaceAll(ruleR, "*", ".*")
		if !strings.HasPrefix(hr.RuleText, "|") {
			reg = "^" + reg
		}
		if strings.HasSuffix(hr.RuleText, "^") {
			reg = reg + "$"
		}
		domainRegex[reg] = struct{}{}
	}
	for k := range domain {
		domainSuffix["."+k] = struct{}{}
	}

	r := Ruleset{}
	r.Version = 1
	r.Rules = []map[string][]any{
		{
			"domain":         lo.Map[string, any](lo.Keys(domain), func(item string, index int) any { return item }),
			"domain_suffix":  lo.Map[string, any](lo.Keys(domainSuffix), func(item string, index int) any { return item }),
			"domain_regex":   lo.Map[string, any](lo.Keys(domainRegex), func(item string, index int) any { return item }),
			"domain_keyword": lo.Map[string, any](lo.Keys(domainKeyword), func(item string, index int) any { return item }),
		},
	}
	return &r, nil
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
