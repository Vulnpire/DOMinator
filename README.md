# DOMinator

is a multithreaded tool designed to detect potential DOM-based XSS vulnerabilities by analyzing inline JavaScript in web pages. It identifies unsafe JavaScript patterns that could lead to security risks. The tool is highly customizable, featuring options for concurrency, rate limiting, and retry mechanisms.

## Features
- **Automated Scanning**: Fetches web pages, extracts inline scripts, and scans for unsafe JavaScript patterns.
- **Concurrency**: Supports multiple workers to scan multiple URLs simultaneously.
- **Rate Limiting**: Prevents overwhelming servers with adjustable request intervals.
- **Retry Logic**: Implements dynamic handling of `Retry-After` headers to respect server-imposed delays.
- **Customizable**: Provides flags for configuring concurrency, rate limits, verbosity, and retries.

## Requirements

- Go 1.23.2 or higher

Install:
`go install -v github.com/Vulnpire/dominator@latest`

## Usage
Run the script with a list of URLs provided via standard input:

Possible DOM XSS vulnerabilities detected in http://example.com:80/Contact-us.aspx:
Pattern '(?i)document\.write\(' found in script:

    var test = "<iframe src='http://blockchain.info' width='1' height='1'></iframe>";
    document.write(test); 

Possible DOM XSS vulnerabilities detected in http://examplee.com:80/Pricings.php:
Pattern '(?i)setTimeout\(' found in script:

    function getelem(objId) {
        return document.getElementById(objId);
    }

    function log(msg) {
        console.log("LOG: " + msg);
    }

    var taintedVariable = location.href.split("#")[1];
    setTimeout("var x=" + taintedVariable, 500);

```
cat urls.txt | ./dominator [options]
```

### Flags
| Flag           | Default | Description |
|----------------|---------|-------------|
| `-c`           | `5`     | Number of concurrent workers. |
| `-rl`          | `1000`  | Rate limit in milliseconds between requests. |
| `-r`           | `false` | Enable dynamic handling of `Retry-After` headers. |
| `-v`           | `false` | Show verbose error messages. |

### Example
```
cat urls.txt | ./dominator -c 10 -rl 500 -r -v
```
This example runs the scanner with 10 concurrent workers, a 500ms rate limit, and enables verbose error messages and `Retry-After` handling.

## Output
The script outputs findings directly to the console. Example output:

```
Possible DOM XSS vulnerabilities detected in https://example.com:
Pattern '(?i)innerHTML\s*=' found in script:
<script>document.getElementById('test').innerHTML = userInput;</script>
```

If verbose mode (`-v`) is enabled, errors encountered during scanning will also be printed.

## How It Works
1. **Fetch URL**: Retrieves the HTML source of the target URL.
2. **Extract Scripts**: Parses the HTML to extract inline `<script>` tags.
3. **Scan Patterns**: Matches the script content against a predefined list of unsafe JavaScript patterns.
4. **Output Findings**: Reports any matches as potential vulnerabilities.

## Unsafe Patterns
The tool scans for the following JavaScript patterns:
- `innerHTML`, `outerHTML` assignments
- `document.write`
- `eval`
- `setTimeout`, `setInterval`
- Access to `location.href`, `location.hash`, `location.search`
- Access to `document.cookie`, `localStorage`, `sessionStorage`
- Inline JavaScript in attributes (e.g., `src="javascript:"`)
- Unsafe `addEventListener` usage

## Enhancements
Future improvements could include:
- Scanning external JavaScript files.
- Adding support for analyzing HTML attributes (e.g., `onclick`, `onerror`).
- Dynamic analysis using browser automation tools like Puppeteer.
- Exploitation testing for confirmed vulnerabilities. (not sure)

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Disclaimer
This tool is intended for educational and ethical testing purposes only. Use it responsibly and only on targets you are authorized to test.
