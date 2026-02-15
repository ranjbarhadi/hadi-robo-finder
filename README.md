# HADI ROBO FINDER

A powerful command-line reconnaissance tool for bug bounty hunters that discovers hidden paths by analyzing historical robots.txt files from the Wayback Machine.

## Overview

HADI ROBO FINDER queries archive.org for all historical snapshots of a target's `/robots.txt` file, extracts all disallowed paths, allowed paths, sitemaps, and URLs, then presents a deduplicated list of **complete URLs** (not just paths) that may reveal hidden or forgotten endpoints.

## Features

- **Historical Analysis**: Retrieves all archived versions of robots.txt from Wayback Machine
- **Date Filtering**: Optional year-based filtering to focus on recent snapshots (e.g., from 2020 onwards)
- **Comprehensive Extraction**: Parses Disallow, Allow, Sitemap, and other URL references
- **Full URL Output**: Converts relative paths to complete URLs (e.g., `/admin/` → `https://example.com/admin/`)
- **Concurrent Processing**: Fast concurrent fetching with built-in rate limiting
- **Deduplication**: Automatically merges and deduplicates all discovered URLs
- **Verbose Mode**: Detailed progress reporting for transparency
- **Detailed Help**: Comprehensive help documentation with `-h` flag
- **Production Ready**: Clean error handling, timeout management, and graceful failure recovery

## Installation

### Quick Install with go install

The easiest way to install HADI ROBO FINDER:

```bash
go install github.com/ranjbarhadi/hadi-robo-finder@latest
```

This installs the binary directly to your `$GOPATH/bin` directory (usually `~/go/bin`).

Make sure `$GOPATH/bin` is in your PATH:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Then use it directly:
```bash
hadi-robo-finder https://example.com
```

### Build from Source (for development)

If you want to modify or develop the tool:

```bash
# Clone the repository
git clone https://github.com/ranjbarhadi/hadi-robo-finder.git
cd hadi-robo-finder

# Build the binary
go build -o hadi-robo-finder main.go

# Run it
./hadi-robo-finder https://example.com
```

### Requirements

- Go 1.21 or higher
- Internet connection to query archive.org

## Usage

### Basic Usage

```bash
./hadi-robo-finder https://example.com
```

### Verbose Mode

Get detailed progress information:

```bash
./hadi-robo-finder -v https://example.com
```

Or with flag after URL:

```bash
./hadi-robo-finder https://example.com -v
```

### Help Information

Get detailed help and usage information:

```bash
./hadi-robo-finder -h
```

This displays comprehensive documentation including:
- Description of the tool
- Command-line options
- How it works step-by-step
- Technical details
- Examples
- Use cases and ethical guidelines

### Date Filtering

Filter snapshots by year to focus on recent results:

```bash
./hadi-robo-finder -year 2020 https://example.com
```

This will only fetch robots.txt snapshots from January 1st, 2020 onwards, which:
- Makes the scan faster (fewer snapshots to process)
- Focuses on more recent/relevant paths
- Reduces noise from very old archived content

**Combine with verbose mode:**
```bash
./hadi-robo-finder -v -year 2022 https://example.com
```

### Examples

**Simple domain:**

```bash
./hadi-robo-finder https://tesla.com
```

**Without scheme (auto-adds https://):**

```bash
./hadi-robo-finder example.com
```

**Verbose output:**

```bash
./hadi-robo-finder -v https://microsoft.com
```

**Filter by year (2020 onwards):**

```bash
./hadi-robo-finder -year 2020 https://example.com
```

**Save results to file:**

```bash
./hadi-robo-finder https://example.com > results.txt
```

## Output

### Standard Mode

```
https://example.com/admin/
https://example.com/api/
https://example.com/api/v1/
https://example.com/backup/
https://example.com/config/
https://example.com/old/
https://example.com/private/
https://example.com/test/
```

### Verbose Mode

```
[+] Target: https://example.com/robots.txt
[+] Found 42 snapshots
[+] Fetching: https://web.archive.org/web/20200101000000/https://example.com/robots.txt
[+] Extracted 8 new paths
[+] Fetching: https://web.archive.org/web/20210601120000/https://example.com/robots.txt
[+] Extracted 3 new paths
...
[+] Total unique paths: 156

https://example.com/admin/
https://example.com/api/
https://example.com/api/v1/
...
```

## How It Works

1. **Input Validation**: Validates and normalizes the target URL
2. **CDX API Query**: Queries Wayback Machine's CDX API for all robots.txt snapshots
3. **Concurrent Fetching**: Downloads archived robots.txt files using rate-limited workers
4. **Path Extraction**: Parses each file for:
   - `Disallow:` directives
   - `Allow:` directives
   - `Sitemap:` URLs
   - Other URL references
5. **URL Conversion**: Converts all relative paths to complete absolute URLs
6. **Deduplication**: Merges all URLs into a unique, sorted list
7. **Output**: Prints all discovered complete URLs to stdout

## Technical Details

- **Language**: Go 1.21+
- **Concurrency**: 5 concurrent workers (configurable)
- **Rate Limiting**: 200ms delay between requests
- **Timeout**: 30-second HTTP timeout
- **API**: Wayback Machine CDX API

## Configuration

You can modify these constants in `main.go`:

```go
const (
    maxWorkers = 5                  // Concurrent workers
    timeout    = 30 * time.Second   // HTTP timeout
)
```

## Error Handling

The tool gracefully handles:

- Network errors and timeouts
- Archive.org downtime or rate limiting
- Invalid responses
- Missing or malformed robots.txt files

If a snapshot fails to fetch, the tool continues processing remaining snapshots.

## Use Cases

- **Bug Bounty Reconnaissance**: Discover forgotten or hidden endpoints
- **Security Research**: Identify potentially sensitive paths
- **Web Archiving Analysis**: Study how robots.txt evolved over time
- **Penetration Testing**: Enumerate historical attack surface

## Ethical Use

This tool is intended for:

- Authorized security testing
- Bug bounty programs
- Security research
- Educational purposes

**Always ensure you have permission to test target systems.**

## Troubleshooting

**No snapshots found:**

- The domain may not be archived on Wayback Machine
- Try older or more popular domains

**Timeout errors:**

- Archive.org may be experiencing high load
- Increase the timeout constant

**Rate limiting:**

- The tool includes built-in delays
- Reduce `maxWorkers` if needed

## License

This tool is provided as-is for educational and security research purposes.

## Contributing

Feel free to submit issues or pull requests for improvements.

## Author

Built for ethical bug bounty hunters and security researchers.

---

**Happy Hunting! 🔍**
