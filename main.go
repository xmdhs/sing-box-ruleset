package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
)

func main() {
	_, adgNoReg, err := adguard(context.Background(), &http.Client{})
	if err != nil {
		panic(err)
	}
	os.MkdirAll("output", 0777)
	write("output/AdGuardSDNSFilter.json", adgNoReg)
	write("output/AdGuardSDNSFilter-NoRegex.json", adgNoReg)
}

func write(name string, ruleSet *Ruleset) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetEscapeHTML(false)
	e.SetIndent("", "    ")
	err = e.Encode(ruleSet)
	if err != nil {
		panic(err)
	}
}
