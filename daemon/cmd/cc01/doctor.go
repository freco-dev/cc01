package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

func runDoctor(args []string) error {
	set := flag.NewFlagSet("doctor", flag.ContinueOnError)
	socket := socketFlag(set)
	asJSON := set.Bool("json", false, "JSON chiqarish")

	if err := set.Parse(args); err != nil {
		return err
	}

	client, closer, err := connect(*socket)
	if err != nil {
		// Demon ishlamayotgan bo'lsa ham tekshiruvlarni bajaramiz:
		// `doctor` ning butun ma'nosi — demon NIMA UCHUN ishlamayotganini
		// aytish.
		fmt.Fprintf(os.Stderr, "demonga ulanib bo'lmadi, mahalliy tekshiruv:\n\n")
		return printChecks(localChecks(), *asJSON)
	}
	defer closer()

	response, err := client.Doctor(context.Background(), &cc01v1.DoctorRequest{})
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(response)
	}

	if err := printChecks(response.GetChecks(), false); err != nil {
		return err
	}

	if !response.GetHealthy() {
		os.Exit(1)
	}
	return nil
}

func printChecks(checks []*cc01v1.Check, asJSON bool) error {
	if asJSON {
		return emitJSON(&cc01v1.DoctorResponse{Checks: checks, Healthy: allOK(checks)})
	}

	for _, check := range checks {
		fmt.Printf("%s %-16s %s\n", marker(check.GetStatus()), check.GetName(), check.GetDetail())

		// Tuzatish yo'li muammo bilan YONMA-YON ko'rsatiladi:
		// foydalanuvchi hujjat qidirmasligi kerak.
		if remediation := check.GetRemediation(); remediation != "" {
			for line := range splitLines(remediation) {
				fmt.Printf("    %s\n", line)
			}
		}
	}

	return nil
}

func marker(status cc01v1.Check_Status) string {
	switch status {
	case cc01v1.Check_STATUS_OK:
		return "✔"
	case cc01v1.Check_STATUS_WARN:
		return "!"
	default:
		return "✘"
	}
}

func allOK(checks []*cc01v1.Check) bool {
	for _, check := range checks {
		if check.GetStatus() == cc01v1.Check_STATUS_FAIL {
			return false
		}
	}
	return true
}

func splitLines(text string) func(func(string) bool) {
	return func(yield func(string) bool) {
		start := 0
		for i := range len(text) {
			if text[i] != '\n' {
				continue
			}
			if !yield(text[start:i]) {
				return
			}
			start = i + 1
		}
		if start < len(text) {
			yield(text[start:])
		}
	}
}
