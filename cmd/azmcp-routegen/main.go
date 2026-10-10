package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"azmcp/internal/core"
)

const usage = "usage: azmcp-routegen [--check|--write] [--manifest PATH] [--seed PATH --upstream PATH --review PATH]\n"

func run(args []string, stdout io.Writer) error {
	write := false
	manifestPath := "fixtures/reviewed-routes/v1-observability-1.json"
	seedPath, catalogPath, reviewPath := "", "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--check":
			write = false
		case "--write":
			write = true
		case "--help", "-h":
			_, err := io.WriteString(stdout, usage)
			return err
		case "--manifest", "--seed", "--upstream", "--review":
			flag := args[i]
			i++
			if i == len(args) {
				return fmt.Errorf("%s requires a path", flag)
			}
			switch flag {
			case "--manifest":
				manifestPath = args[i]
			case "--seed":
				seedPath = args[i]
			case "--upstream":
				catalogPath = args[i]
			case "--review":
				reviewPath = args[i]
			}
		default:
			return fmt.Errorf("unknown argument %q; use --help", args[i])
		}
	}
	importing := seedPath != "" || catalogPath != "" || reviewPath != ""
	var manifest core.RouteManifest
	if importing {
		if seedPath == "" || catalogPath == "" || reviewPath == "" {
			return fmt.Errorf("--seed, --upstream, and --review must be supplied together")
		}
		seedAbsolute, err := filepath.Abs(seedPath)
		if err != nil {
			return err
		}
		manifestAbsolute, err := filepath.Abs(manifestPath)
		if err != nil {
			return err
		}
		if seedAbsolute == manifestAbsolute {
			return fmt.Errorf("--seed and --manifest must name different files")
		}
		seedInfo, err := os.Stat(seedPath)
		if err != nil {
			return err
		}
		if outputInfo, err := os.Stat(manifestPath); err == nil {
			if os.SameFile(seedInfo, outputInfo) {
				return fmt.Errorf("--seed and --manifest must name different files")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		raw, err := os.ReadFile(seedPath)
		if err != nil {
			return err
		}
		seed, err := core.ParseManifestForGeneration(raw)
		if err != nil {
			return err
		}
		raw, err = os.ReadFile(catalogPath)
		if err != nil {
			return err
		}
		catalog, err := core.ParseCatalog(raw)
		if err != nil {
			return err
		}
		raw, err = os.ReadFile(reviewPath)
		if err != nil {
			return err
		}
		review, err := core.ParseReview(raw)
		if err != nil {
			return err
		}
		manifest, err = core.GenerateManifest(seed, catalog, review)
		if err != nil {
			return err
		}
	} else {
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		manifest, err = core.ParseManifest(raw)
		if err != nil {
			return err
		}
	}
	canonical, err := core.CanonicalManifest(manifest)
	if err != nil {
		return err
	}
	if write {
		if err = os.WriteFile(manifestPath, canonical, 0644); err != nil {
			return err
		}
	} else {
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		if importing {
			if _, err = core.ParseManifestForGeneration(raw); err != nil {
				return err
			}
		}
		if !bytes.Equal(raw, canonical) {
			reason := "not canonical"
			if importing {
				reason = "not current with the pinned route inputs"
			}
			return fmt.Errorf("%s is %s; run azmcp-routegen --write --manifest %s", manifestPath, reason, manifestPath)
		}
	}
	_, err = fmt.Fprintf(stdout, "validated %d routes and %d schemas for %s\n", len(manifest.Routes), len(manifest.Schemas), manifest.PolicyVersion)
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
