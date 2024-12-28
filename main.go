package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

var UnsafePatterns = []string{
	`(?i)innerHTML\s*=`,          // DOM manipulation with innerHTML
	`(?i)outerHTML\s*=`,          // DOM manipulation with outerHTML
	`(?i)document\.write\(`,      // Writing to the DOM directly
	`(?i)eval\(`,                 // Executing arbitrary code
	`(?i)setTimeout\(`,           // Dynamic code execution
	`(?i)setInterval\(`,          // Dynamic code execution
	`(?i)location\.href`,         // Accessing URL
	`(?i)location\.hash`,         // Accessing hash fragment
	`(?i)location\.search`,       // Accessing query parameters
	`(?i)document\.cookie`,       // Accessing cookies
	`(?i)localStorage`,           // Accessing local storage
	`(?i)sessionStorage`,         // Accessing session storage
	`(?i)src\s*=\s*['"]javascript:`, // Inline JavaScript in attributes
	`(?i)\+.*location`,           // String concatenation with location
	`(?i)\.addEventListener\(['"].*['"],\s*function`, // Unsafe event listeners
} // More soon

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
}

func getRandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

func randomDelay(rateLimit int) {
	delay := time.Duration(rand.Intn(rateLimit)+rateLimit/2) * time.Millisecond
	time.Sleep(delay)
}

// This fetches the HTML source of a given URL through allorigins.win proxy
func FetchURL(url string, rateLimit int, retryAfter bool) (string, error) {
	proxyURL := fmt.Sprintf("https://api.allorigins.win/raw?url=%s", url)
	var lastErr error
	for retries := 0; retries < 5; retries++ {
		req, err := http.NewRequest("GET", proxyURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("User-Agent", getRandomUserAgent())

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch URL: %v", err)
			randomDelay(rateLimit)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			lastErr = fmt.Errorf("rate limited (HTTP 429)")
			if retryAfter {
				retryHeader := resp.Header.Get("Retry-After")
				if retryHeader != "" {
					retryDelay, err := strconv.Atoi(retryHeader)
					if err == nil {
						time.Sleep(time.Duration(retryDelay) * time.Second)
						continue
					}
				}
			}
			randomDelay(rateLimit)
			continue
		} else if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("non-200 response: %d", resp.StatusCode)
		}

		var body strings.Builder
		_, err = io.Copy(&body, resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		return body.String(), nil
	}
	return "", lastErr
}

// parses the HTML and extracts inline scripts
func ExtractScripts(htmlSource string) ([]string, error) {
	doc, err := html.Parse(strings.NewReader(htmlSource))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %v", err)
	}

	var scripts []string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" && n.FirstChild != nil {
			scripts = append(scripts, n.FirstChild.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	return scripts, nil
}

// ScanForUnsafePatterns scans JavaScript code for unsafe patterns
func ScanForUnsafePatterns(scripts []string) []string {
	var findings []string
	for _, script := range scripts {
		for _, pattern := range UnsafePatterns {
			matched, _ := regexp.MatchString(pattern, script)
			if matched {
				findings = append(findings, fmt.Sprintf("Pattern '%s' found in script:\n%s", pattern, script))
			}
		}
	}
	return findings
}

func worker(urls <-chan string, wg *sync.WaitGroup, findingsChan chan<- string, showErrors bool, rateLimit int, retryAfter bool) {
	defer wg.Done()

	for url := range urls {
		if url == "" {
			continue
		}

		randomDelay(rateLimit) // random delay before each request
		htmlSource, err := FetchURL(url, rateLimit, retryAfter)
		if err != nil {
			if showErrors {
				findingsChan <- fmt.Sprintf("Error fetching URL %s: %v", url, err)
			}
			continue
		}

		inlineScripts, err := ExtractScripts(htmlSource)
		if err != nil {
			if showErrors {
				findingsChan <- fmt.Sprintf("Error extracting scripts from URL %s: %v", url, err)
			}
			continue
		}

		findings := ScanForUnsafePatterns(inlineScripts)
		if len(findings) > 0 {
			findingsChan <- fmt.Sprintf("Possible DOM XSS vulnerabilities detected in %s:\n%s", url, strings.Join(findings, "\n"))
		} else if showErrors {
			findingsChan <- fmt.Sprintf("No potential DOM XSS vulnerabilities detected in %s.", url)
		}
	}
}

func main() {
	var concurrency int
	var rateLimit int
	var showErrors bool
	var retryAfter bool

	flag.IntVar(&concurrency, "c", 5, "Number of concurrent workers")
	flag.IntVar(&rateLimit, "rl", 1000, "Rate limit in milliseconds between requests")
	flag.BoolVar(&showErrors, "v", false, "Show verbose error messages")
	flag.BoolVar(&retryAfter, "r", false, "Use Retry-After header if present")
	flag.Parse()

	urls := make(chan string)
	findingsChan := make(chan string)

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(urls, &wg, findingsChan, showErrors, rateLimit, retryAfter)
	}

	var findingsWG sync.WaitGroup
	findingsWG.Add(1)
	go func() {
		defer findingsWG.Done()
		for finding := range findingsChan {
			fmt.Println(finding)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()
		urls <- url
	}
	close(urls)

	wg.Wait()
	close(findingsChan)
	findingsWG.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading input: %v\n", err)
	}
}
