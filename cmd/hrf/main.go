package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	cdxAPI      = "http://web.archive.org/cdx/search/cdx"
	snapshotURL = "https://web.archive.org/web/%sid_/%s"
	maxWorkers  = 5 // Concurrent workers to avoid overwhelming archive.org
	timeout     = 30 * time.Second
)

// Snapshot represents a Wayback Machine snapshot
type Snapshot struct {
	Timestamp string
	URL       string
}

// Config holds application configuration
type Config struct {
	TargetURL string
	BaseURL   string // Base URL for constructing full paths (e.g., https://example.com)
	FromYear  string // Starting year for filtering snapshots (YYYY format, empty = all time)
	Verbose   bool
	Client    *http.Client
}

// PathCollector manages unique path collection
type PathCollector struct {
	mu    sync.Mutex
	paths map[string]bool
}

func main() {
	// Parse command-line arguments manually to allow flags at any position
	var verbose bool
	var help bool
	var targetURL string
	var fromYear string

	// Iterate through all arguments
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-v":
			verbose = true
		case "-h":
			help = true
		case "-year":
			// Next argument should be the year
			if i+1 < len(os.Args) {
				fromYear = os.Args[i+1]
				i++ // Skip the next argument since we consumed it
			} else {
				fmt.Fprintf(os.Stderr, "Error: -year flag requires a year value\n")
				os.Exit(1)
			}
		default:
			// Assume it's the target URL
			if targetURL == "" {
				targetURL = arg
			}
		}
	}

	// Display help if requested
	if help {
		printHelp()
		os.Exit(0)
	}

	// Get target URL from arguments
	if targetURL == "" {
		fmt.Fprintf(os.Stderr, "Error: No target URL provided\n")
		fmt.Fprintf(os.Stderr, "Usage: hrf [-v] [-h] [-year YYYY] <target-url>\n")
		fmt.Fprintf(os.Stderr, "Example: hrf -year 2020 https://example.com\n")
		fmt.Fprintf(os.Stderr, "Use -h for detailed help\n")
		os.Exit(1)
	}

	// Validate year if provided
	if fromYear != "" {
		if len(fromYear) != 4 {
			fmt.Fprintf(os.Stderr, "Error: Year must be in YYYY format (e.g., 2020)\n")
			os.Exit(1)
		}
		// Simple validation - check if it's a number
		for _, c := range fromYear {
			if c < '0' || c > '9' {
				fmt.Fprintf(os.Stderr, "Error: Year must be a valid number (e.g., 2020)\n")
				os.Exit(1)
			}
		}
	}

	if verbose {
		fmt.Printf("[*] Starting HADI ROBO FINDER\n")
		fmt.Printf("[*] Input URL: %s\n", targetURL)
		if fromYear != "" {
			fmt.Printf("[*] Date filter: From %s to now\n", fromYear)
		}
	}

	// Validate and normalize URL
	normalizedURL, baseURL, err := validateAndNormalizeURL(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("[*] Normalized robots.txt URL: %s\n", normalizedURL)
		fmt.Printf("[*] Base URL for path construction: %s\n", baseURL)
		fmt.Printf("[*] HTTP timeout: %v\n", timeout)
		fmt.Printf("[*] Concurrent workers: %d\n", maxWorkers)
		fmt.Println()
	}

	// Create configuration
	config := &Config{
		TargetURL: normalizedURL,
		BaseURL:   baseURL,
		FromYear:  fromYear,
		Verbose:   verbose,
		Client: &http.Client{
			Timeout: timeout,
		},
	}

	// Run the main process
	if err := run(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// printHelp displays detailed help information
func printHelp() {
	fmt.Println("HADI ROBO FINDER - Historical Robots.txt Reconnaissance Tool")
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Println("  A powerful bug bounty reconnaissance tool that discovers hidden paths by")
	fmt.Println("  analyzing historical robots.txt files from the Wayback Machine (archive.org).")
	fmt.Println()
	fmt.Println("  This tool queries the Wayback Machine for ALL archived snapshots of a target's")
	fmt.Println("  /robots.txt file, extracts every disallowed path, allowed path, sitemap URL,")
	fmt.Println("  and referenced URL, then outputs a deduplicated list of complete URLs that may")
	fmt.Println("  reveal forgotten endpoints, hidden admin panels, backup directories, APIs,")
	fmt.Println("  and other security-relevant paths.")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  hrf [-v] [-h] [-year YYYY] <target-url>")
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("  -v          Enable verbose mode")
	fmt.Println("              Shows detailed progress including:")
	fmt.Println("                - Number of snapshots found in Wayback Machine")
	fmt.Println("                - Each snapshot URL being processed")
	fmt.Println("                - Number of paths extracted from each snapshot")
	fmt.Println("                - Total unique URLs discovered")
	fmt.Println("                - Error messages for failed requests (continues processing)")
	fmt.Println()
	fmt.Println("  -h          Display this detailed help information")
	fmt.Println()
	fmt.Println("  -year YYYY  Filter snapshots from specified year to now (optional)")
	fmt.Println("              Only includes robots.txt snapshots from YYYY onwards")
	fmt.Println("              Examples: -year 2020, -year 2018")
	fmt.Println("              Default: All available snapshots (no date filter)")
	fmt.Println()
	fmt.Println("ARGUMENTS:")
	fmt.Println("  target-url    The target domain to analyze (with or without protocol)")
	fmt.Println("                Examples: https://example.com, example.com, http://site.org")
	fmt.Println()
	fmt.Println("HOW IT WORKS:")
	fmt.Println("  1. Validates and normalizes the input URL")
	fmt.Println("  2. Queries Wayback Machine CDX API for all robots.txt snapshots")
	fmt.Println("  3. Concurrently fetches each archived robots.txt (rate-limited)")
	fmt.Println("  4. Parses each file for:")
	fmt.Println("       - Disallow: directives (paths blocked from crawlers)")
	fmt.Println("       - Allow: directives (explicitly allowed paths)")
	fmt.Println("       - Sitemap: URLs (XML sitemaps)")
	fmt.Println("       - Any other URL references")
	fmt.Println("  5. Converts relative paths to absolute URLs")
	fmt.Println("  6. Deduplicates and sorts all discovered URLs")
	fmt.Println("  7. Outputs the complete list to stdout")
	fmt.Println()
	fmt.Println("TECHNICAL DETAILS:")
	fmt.Println("  - Concurrent Workers: 5 (controlled to avoid overwhelming archive.org)")
	fmt.Println("  - Rate Limiting: 200ms delay between requests")
	fmt.Println("  - HTTP Timeout: 30 seconds per request")
	fmt.Println("  - Error Handling: Graceful - continues processing on individual failures")
	fmt.Println("  - Output Format: Complete URLs, one per line, alphabetically sorted")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  Basic usage:")
	fmt.Println("    hrf https://example.com")
	fmt.Println()
	fmt.Println("  Verbose mode (see detailed progress):")
	fmt.Println("    hrf -v https://tesla.com")
	fmt.Println()
	fmt.Println("  Without protocol (auto-adds https://):")
	fmt.Println("    hrf example.com")
	fmt.Println()
	fmt.Println("  Save results to file:")
	fmt.Println("    hrf https://example.com > discovered_urls.txt")
	fmt.Println()
	fmt.Println("  Filter by year (snapshots from 2020 onwards):")
	fmt.Println("    hrf -year 2020 https://example.com")
	fmt.Println()
	fmt.Println("  Combine verbose mode with year filter:")
	fmt.Println("    hrf -v -year 2022 https://example.com")
	fmt.Println()
	fmt.Println("  Pipe to other tools:")
	fmt.Println("    hrf https://example.com | httpx -status-code")
	fmt.Println("    hrf https://example.com | grep '/api/' | nuclei")
	fmt.Println("    hrf -year 2023 https://target.com | httpx -mc 200")
	fmt.Println()
	fmt.Println("USE CASES:")
	fmt.Println("  - Bug bounty reconnaissance: Find forgotten endpoints and hidden paths")
	fmt.Println("  - Security research: Identify potentially sensitive directories")
	fmt.Println("  - Penetration testing: Enumerate historical attack surface")
	fmt.Println("  - Web archiving analysis: Study how robots.txt evolved over time")
	fmt.Println()
	fmt.Println("ETHICAL USE:")
	fmt.Println("  This tool is intended ONLY for:")
	fmt.Println("    ✓ Authorized security testing")
	fmt.Println("    ✓ Bug bounty programs")
	fmt.Println("    ✓ Security research")
	fmt.Println("    ✓ Educational purposes")
	fmt.Println()
	fmt.Println("  Always ensure you have permission to test target systems.")
	fmt.Println("  The tool only queries public archive.org data - it does NOT")
	fmt.Println("  directly interact with target websites.")
	fmt.Println()
	fmt.Println("OUTPUT:")
	fmt.Println("  Complete URLs are printed to stdout, one per line:")
	fmt.Println("    https://example.com/admin/")
	fmt.Println("    https://example.com/api/v1/")
	fmt.Println("    https://example.com/backup/")
	fmt.Println("    https://example.com/private/config.php")
	fmt.Println()
	fmt.Println("TROUBLESHOOTING:")
	fmt.Println("  'No snapshots found':")
	fmt.Println("    - Domain may not be archived on Wayback Machine")
	fmt.Println("    - Try older or more popular domains for testing")
	fmt.Println()
	fmt.Println("  Timeout errors:")
	fmt.Println("    - Archive.org may be experiencing high load")
	fmt.Println("    - Tool will continue with remaining snapshots")
	fmt.Println()
	fmt.Println("AUTHOR:")
	fmt.Println("  Built for ethical bug bounty hunters and security researchers")
	fmt.Println()
}

// validateAndNormalizeURL validates and normalizes the input URL
// Returns: (robotsURL, baseURL, error)
func validateAndNormalizeURL(input string) (string, string, error) {
	// Add scheme if missing
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	// Parse URL
	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %v", err)
	}

	if parsedURL.Host == "" {
		return "", "", fmt.Errorf("invalid URL: missing host")
	}

	// Build base URL (without path)
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Build normalized URL with /robots.txt
	robotsURL := fmt.Sprintf("%s/robots.txt", baseURL)

	return robotsURL, baseURL, nil
}

// run executes the main logic
func run(config *Config) error {
	if config.Verbose {
		fmt.Printf("==> Phase 1: Querying Wayback Machine\n")
		fmt.Printf("[+] Target: %s\n", config.TargetURL)
	}

	// Fetch snapshots from Wayback Machine
	snapshots, err := fetchSnapshots(config)
	if err != nil {
		return fmt.Errorf("failed to fetch snapshots: %v", err)
	}

	if len(snapshots) == 0 {
		fmt.Println("No snapshots found in archive.org")
		return nil
	}

	if config.Verbose {
		fmt.Printf("[+] Found %d snapshots\n", len(snapshots))
		fmt.Println()
		fmt.Printf("==> Phase 2: Fetching and parsing robots.txt files\n")
	}

	// Collect paths from all snapshots
	collector := &PathCollector{
		paths: make(map[string]bool),
	}

	processSnapshots(config, snapshots, collector)

	if config.Verbose {
		fmt.Println()
		fmt.Printf("==> Phase 3: Results\n")
	}

	// Get unique sorted paths
	uniquePaths := collector.getSortedPaths()

	if config.Verbose {
		fmt.Printf("[+] Total unique paths: %d\n", len(uniquePaths))
		fmt.Println()
	}

	// Print results
	for _, path := range uniquePaths {
		fmt.Println(path)
	}

	return nil
}

// fetchSnapshots retrieves all snapshots from Wayback Machine CDX API
func fetchSnapshots(config *Config) ([]Snapshot, error) {
	// Build CDX API request
	cdxURL := fmt.Sprintf("%s?url=%s&output=json&fl=timestamp,original",
		cdxAPI, url.QueryEscape(config.TargetURL))

	// Add date filter if FromYear is specified
	if config.FromYear != "" {
		// Convert YYYY to YYYYMMDDHHMMSS format (January 1st at midnight)
		fromDate := config.FromYear + "0101000000"
		cdxURL += "&from=" + fromDate
	}

	if config.Verbose {
		fmt.Printf("[+] Querying Wayback Machine CDX API...\n")
		if config.FromYear != "" {
			fmt.Printf("[+] Date filter active: From %s-01-01 to now\n", config.FromYear)
		}
		fmt.Printf("[+] CDX URL: %s\n", cdxURL)
	}

	req, err := http.NewRequest("GET", cdxURL, nil)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		fmt.Printf("[+] Sending HTTP GET request (timeout: %v)...\n", timeout)
	}

	startTime := time.Now()
	resp, err := config.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CDX API request failed: %v", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(startTime)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDX API returned status %d", resp.StatusCode)
	}

	if config.Verbose {
		fmt.Printf("[+] CDX API responded with status %d (took %v)\n", resp.StatusCode, elapsed)
		fmt.Printf("[+] Parsing JSON response...\n")
	}

	// Parse JSON response
	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse CDX response: %v", err)
	}

	if config.Verbose {
		fmt.Printf("[+] Parsed CDX response with %d entries\n", len(data))
	}

	// Skip header row and convert to Snapshot structs
	// Use len(data) directly to avoid negative capacity if data is empty
	snapshots := make([]Snapshot, 0, len(data))
	for i, row := range data {
		if i == 0 {
			continue // Skip header
		}
		if len(row) >= 2 {
			snapshots = append(snapshots, Snapshot{
				Timestamp: row[0],
				URL:       row[1],
			})
		}
	}

	return snapshots, nil
}

// processSnapshots fetches and parses robots.txt from all snapshots concurrently
func processSnapshots(config *Config, snapshots []Snapshot, collector *PathCollector) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)

	for _, snapshot := range snapshots {
		wg.Add(1)
		go func(snap Snapshot) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Add small delay to respect rate limits
			time.Sleep(200 * time.Millisecond)

			// Fetch and process snapshot
			processSnapshot(config, snap, collector)
		}(snapshot)
	}

	wg.Wait()
}

// processSnapshot fetches and parses a single snapshot
func processSnapshot(config *Config, snapshot Snapshot, collector *PathCollector) {
	snapshotURL := fmt.Sprintf(snapshotURL, snapshot.Timestamp, snapshot.URL)

	if config.Verbose {
		fmt.Printf("[+] Fetching: %s\n", snapshotURL)
	}

	req, err := http.NewRequest("GET", snapshotURL, nil)
	if err != nil {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Error creating request for %s: %v\n", snapshotURL, err)
		}
		return
	}

	resp, err := config.Client.Do(req)
	if err != nil {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Error fetching %s: %v\n", snapshotURL, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Status %d for %s\n", resp.StatusCode, snapshotURL)
		}
		return
	}

	// Parse robots.txt content
	paths := parseRobotsTxt(resp.Body, config.BaseURL)

	if config.Verbose && len(paths) > 0 {
		fmt.Printf("[+] Extracted %d new paths\n", len(paths))
	}

	// Add to collector
	collector.addPaths(paths)
}

// parseRobotsTxt extracts paths from robots.txt content and converts them to full URLs
func parseRobotsTxt(reader io.Reader, baseURL string) []string {
	var paths []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract paths from Disallow, Allow, and Sitemap directives
		path := extractPath(line, baseURL)
		if path != "" {
			paths = append(paths, path)
		}
	}

	return paths
}

// extractPath extracts the path portion from a robots.txt directive and converts to full URL
func extractPath(line string, baseURL string) string {
	// Normalize line to lower case for prefix checking, but keep original for value extraction
	lowerLine := strings.ToLower(line)

	// Check for common directives
	// We use lower case directives for case-insensitive matching
	// Only include directives that contain paths
	directives := []string{"disallow:", "allow:", "sitemap:"}

	for _, directive := range directives {
		if strings.HasPrefix(lowerLine, directive) {
			// Extract value after directive from the ORIGINAL line (using the length of the matched directive)
			// This preserves the case of the path itself
			value := strings.TrimSpace(line[len(directive):])

			// Skip empty values
			if value == "" {
				return ""
			}

			// Clean up the path
			value = strings.TrimSpace(value)

			// Handle inline comments
			if idx := strings.Index(value, "#"); idx != -1 {
				value = strings.TrimSpace(value[:idx])
			}

			// Convert to full URL
			return buildFullURL(value, baseURL)
		}
	}

	// Check if line contains a URL (for other references)
	if strings.HasPrefix(lowerLine, "http://") || strings.HasPrefix(lowerLine, "https://") {
		return line
	}

	return ""
}

// buildFullURL converts a relative path to a full URL
func buildFullURL(path string, baseURL string) string {
	// If already a full URL, return as-is
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Combine base URL with path
	return baseURL + path
}

// addPaths adds paths to the collector (thread-safe)
func (pc *PathCollector) addPaths(paths []string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, path := range paths {
		pc.paths[path] = true
	}
}

// getSortedPaths returns all unique paths sorted alphabetically
func (pc *PathCollector) getSortedPaths() []string {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	paths := make([]string, 0, len(pc.paths))
	for path := range pc.paths {
		paths = append(paths, path)
	}

	sort.Strings(paths)
	return paths
}
