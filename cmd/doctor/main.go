// Command doctor is the TraitX integration self-check.
//
//	TRAITX_BASE_URL=https://traitx.allytech.sa \
//	TRAITX_PRIVATE_KEY=trx_pvk_... \
//	TRAITX_APPLICATION_ID=ccf2d2a0-... \
//	go run ./cmd/doctor [collector-request-id]
//
// Pass a real requestId from your browser collector to also verify that the key
// is accepted, that IP enrichment is attached and that the policy chain returns
// an action. See SPEC.md §13.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	traitx "github.com/traitx-allytech/traitx-sdk-go"
)

func main() {
	baseURL := os.Getenv("TRAITX_BASE_URL")
	apiKey := os.Getenv("TRAITX_PRIVATE_KEY")
	if baseURL == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr, "set TRAITX_BASE_URL and TRAITX_PRIVATE_KEY")
		os.Exit(2)
	}

	client, err := traitx.New(traitx.Config{
		BaseURL:       baseURL,
		APIKey:        apiKey,
		ApplicationID: os.Getenv("TRAITX_APPLICATION_ID"),
		Timeout:       5 * time.Second,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var probe string
	if len(os.Args) > 1 {
		probe = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report := client.Doctor(ctx, probe)
	for _, finding := range report.Findings {
		status := "FAIL"
		if finding.OK {
			status = "ok  "
		}
		fmt.Printf("%s  %-32s %s\n", status, finding.Check, finding.Detail)
	}

	fmt.Println()
	if report.OK {
		fmt.Println("All checks passed.")
		return
	}
	fmt.Println("Some checks failed — see above.")
	os.Exit(1)
}
