package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	// Ensure the tag is provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: tag-modules <tag>")
		os.Exit(1)
	}
	tag := os.Args[1]

	// Get current working directory (repo root)
	rootDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting working directory: %v\n", err)
		os.Exit(1)
	}

	var rootModule string
	var moduleTags []string

	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}

		// Check if the file is a go.mod
		if info.Name() == "go.mod" {
			moduleName, err := parseModuleName(path)
			if err != nil {
				fmt.Printf("Error reading go.mod at %s: %v\n", path, err)
				return nil
			}

			// Determine the root module (first go.mod encountered)
			if rootModule == "" {
				rootModule = moduleName
			}

			// Remove the root module prefix from the module path
			relativeModule := strings.TrimPrefix(moduleName, rootModule)
			relativeModule = strings.TrimPrefix(relativeModule, "/") // Remove leading slash if present

			// Determine the tag format
			var gitTag string
			if relativeModule == "" {
				// Root-level tag
				gitTag = tag
			} else {
				// Submodule tag: format as "relative_module/v0.1.3"
				gitTag = fmt.Sprintf("%s/%s", relativeModule, tag)
			}

			moduleTags = append(moduleTags, gitTag)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking the directory: %v\n", err)
		os.Exit(1)
	}

	for _, gitTag := range moduleTags {
		fmt.Printf("%s ", gitTag)
		cmd := exec.Command("git", "tag", gitTag)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to tag %s: %v\n", gitTag, err)
		}
	}
	fmt.Printf("\n")
}

// parseModuleName extracts the module name from a go.mod file
func parseModuleName(goModPath string) (string, error) {
	file, err := os.Open(goModPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}

	return "", fmt.Errorf("no module name found in %s", goModPath)
}
