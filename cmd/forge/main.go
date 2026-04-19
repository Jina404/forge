package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Jina404/forge/pkg/detector"
	"github.com/Jina404/forge/pkg/engine"
	"github.com/spf13/cobra"
)

func main() {
	var (
		targetURL   string
		concurrency int
		duration    time.Duration
		timeout     time.Duration
		fuzzRatio   float64
		fuzzParam   string
		payloadFile string
		baseline    bool
	)

	rootCmd := &cobra.Command{
		Use:   "forge",
		Short: "Forge - Advanced Resilience & Security Testing Tool",
		Long:  `Forge combines high-concurrency load testing with advanced vulnerability detection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			runner, err := engine.NewRunner(engine.Config{
				TargetURL:         targetURL,
				Method:            "GET",
				Concurrency:       concurrency,
				Duration:          duration,
				Timeout:           timeout,
				Headers:           map[string]string{"User-Agent": "Forge/2.0"},
				FuzzRatio:         fuzzRatio,
				FuzzParam:         fuzzParam,
				PayloadFile:       payloadFile,
				EstablishBaseline: baseline,
			})
			if err != nil {
				return err
			}

			fmt.Printf("🚀 Forge v2.0 - Resilience & Security Test\n")
			fmt.Printf("   Target:      %s\n", targetURL)
			fmt.Printf("   Workers:     %d\n", concurrency)
			if fuzzRatio > 0 {
				fmt.Printf("   Fuzzing:     %.0f%% (%d workers)\n", fuzzRatio*100, int(float64(concurrency)*fuzzRatio))
				fmt.Printf("   Parameter:   %s\n", fuzzParam)
			}
			fmt.Printf("   Duration:    %v\n", duration)
			if baseline {
				fmt.Printf("   Baseline:    Established for diff analysis\n")
			}
			fmt.Println("──────────────────────────────────────────")

			start := time.Now()
			runner.Start()
			runner.Wait()
			elapsed := time.Since(start)

			stats := runner.Metrics()
			fmt.Println("\n📊 LOAD TEST RESULTS")
			fmt.Printf("   Requests:       %d total, %.2f req/sec\n", stats.TotalRequests, float64(stats.TotalRequests)/elapsed.Seconds())
			fmt.Printf("   Success Rate:   %.2f%%\n", float64(stats.SuccessRequests)/float64(stats.TotalRequests)*100)
			fmt.Printf("   Latency (avg):  %.2f ms\n", stats.AvgLatencyMs)
			fmt.Printf("   Latency (p99):  %.2f ms\n", stats.MaxLatencyMs) // Simplified

			findings := runner.Findings()
			if len(findings) > 0 {
				fmt.Println("\n🔴 SECURITY FINDINGS")
				fmt.Println("──────────────────────────────────────────")
				for i, f := range findings {
					fmt.Printf("\n[%d] %s (confidence: %.0f%%)\n", i+1, f.Type, f.Confidence*100)
					fmt.Printf("    URL:        %s\n", f.URL)
					fmt.Printf("    Payload:    %s\n", f.Payload)
					fmt.Printf("    Evidence:   %s\n", f.Evidence)
					
					// Detailed explanation
					exp := detector.Explain(f)
					fmt.Printf("\n    📖 %s\n", exp.Description)
					fmt.Printf("    💥 Impact: %s\n", exp.Impact)
					fmt.Printf("    🛡️ Fix: %s\n", exp.Remediation)
				}
			} else if fuzzRatio > 0 {
				fmt.Println("\n✅ No vulnerabilities detected.")
			}

			return nil
		},
	}

	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL (required)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 100, "Number of concurrent workers")
	rootCmd.Flags().DurationVarP(&duration, "duration", "d", 10*time.Second, "Test duration")
	rootCmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Second, "Per-request timeout")
	rootCmd.Flags().Float64Var(&fuzzRatio, "fuzz-ratio", 0.0, "Fraction of workers fuzzing (0.0-1.0)")
	rootCmd.Flags().StringVar(&fuzzParam, "fuzz-param", "", "Parameter template (e.g., '/search?q=FUZZ')")
	rootCmd.Flags().StringVar(&payloadFile, "payloads", "", "Payload file (one per line)")
	rootCmd.Flags().BoolVar(&baseline, "baseline", false, "Capture baseline response for advanced diffing")
	rootCmd.MarkFlagRequired("url")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
