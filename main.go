// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/time/rate"
)

const version = "1.2.0"

var (
	urlFlag         string
	output          string
	preferIPv6      bool
	continueFlag    bool
	verbose         bool
	quiet           bool
	recursive       bool
	parallel        int
	ftpUser         string
	ftpPass         string
	maxDepth        int
	logLevel        string
	userAgent       string
	retryCount      int
	timeout         time.Duration
	proxyURL        string
	httpUser        string
	httpPass        string
	digestAuth      bool
	acceptExt       string
	rejectExt       string
	domains         string
	spanHosts       bool
	relativeOnly    bool
	cookiesFile     string
	spiderMode      bool
	mirrorMode      bool
	convertLinks    bool
	postData        string
	postFile        string
	checksum        string
	http3Enabled    bool
	mimeType        string
	versionFlag     bool
	limitRate       string
	rateLimiter     *rate.Limiter
	downloadedFiles = make(map[string]bool)
	downloadLock    sync.Mutex
	baseHref        string
)

func init() {
	flag.StringVar(&urlFlag, "url", "", "URL to download")
	flag.StringVar(&output, "O", "", "Output file name")
	flag.BoolVar(&preferIPv6, "6", false, "Use IPv6 only")
	flag.BoolVar(&continueFlag, "c", false, "Continue partial downloads")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&quiet, "q", false, "Quiet mode")
	flag.BoolVar(&recursive, "r", false, "Recursive download")
	flag.IntVar(&parallel, "N", 1, "Number of parallel connections")
	flag.StringVar(&ftpUser, "ftp-user", "", "FTP username")
	flag.StringVar(&ftpPass, "ftp-pass", "", "FTP password")
	flag.IntVar(&maxDepth, "l", 5, "Maximum recursion depth")
	flag.StringVar(&logLevel, "log", "info", "Log level (debug/info/warn/error)")
	flag.StringVar(&userAgent, "U", "goget/"+version, "Custom User-Agent")
	flag.IntVar(&retryCount, "tries", 3, "Number of retries")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Connection timeout")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (http://user:pass@host:port)")
	flag.StringVar(&httpUser, "http-user", "", "HTTP username")
	flag.StringVar(&httpPass, "http-pass", "", "HTTP password")
	flag.BoolVar(&digestAuth, "digest", false, "Use Digest authentication")
	flag.StringVar(&acceptExt, "A", "", "Accepted extensions (comma-separated)")
	flag.StringVar(&rejectExt, "R", "", "Rejected extensions (comma-separated)")
	flag.StringVar(&domains, "D", "", "Allowed domains (comma-separated)")
	flag.BoolVar(&spanHosts, "H", false, "Span hosts")
	flag.BoolVar(&relativeOnly, "L", false, "Follow relative links only")
	flag.StringVar(&cookiesFile, "cookies", "", "Cookies file")
	flag.BoolVar(&spiderMode, "spider", false, "Check URL existence without downloading")
	flag.BoolVar(&mirrorMode, "m", false, "Mirror mode with directory structure")
	flag.BoolVar(&convertLinks, "k", false, "Convert links for local viewing")
	flag.StringVar(&postData, "post-data", "", "POST data to send")
	flag.StringVar(&postFile, "post-file", "", "File to upload via POST")
	flag.StringVar(&checksum, "checksum", "", "Checksum verification (md5:hash or sha1:hash)")
	flag.BoolVar(&http3Enabled, "http3", false, "Enable experimental HTTP/3 support")
	flag.StringVar(&mimeType, "mime-type", "", "Filter by MIME type (e.g., 'image/jpeg')")
	flag.BoolVar(&versionFlag, "version", false, "Show version")
	flag.StringVar(&limitRate, "limit-rate", "", "Maximum download rate (e.g., 100k, 1M)")
	flag.Parse()
}

func main() {
	if versionFlag {
		fmt.Printf("goget version %s\n", version)
		os.Exit(0)
	}

	if urlFlag == "" {
		log.Fatal("Error: URL is required")
	}

	if limitRate != "" {
		bytesPerSecond, err := parseRateLimit(limitRate)
		if err != nil {
			log.Fatalf("Error parsing rate limit: %v", err)
		}
		if bytesPerSecond <= 0 {
			log.Fatal("Rate limit must be a positive value")
		}
		rateLimiter = rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond))
	}

	setupLogging()
	loadCookies()
	defer saveCookies()

	parsedURL, err := url.Parse(urlFlag)
	if err != nil {
		log.Fatal("Invalid URL:", err)
	}

	err = download(parsedURL, output, maxDepth)
	if err != nil {
		log.Fatal(err)
	}
}

func parseRateLimit(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}

	var multiplier int64 = 1
	suffixes := map[string]int64{
		"k": 1024,
		"m": 1024 * 1024,
		"g": 1024 * 1024 * 1024,
	}

	for suffix, mult := range suffixes {
		if strings.HasSuffix(s, suffix) {
			multiplier = mult
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}

	bytes, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate format: %v", err)
	}

	return bytes * multiplier, nil
}

type rateLimitedReader struct {
	reader  io.Reader
	limiter *rate.Limiter
}

func newRateLimitedReader(r io.Reader, l *rate.Limiter) *rateLimitedReader {
	return &rateLimitedReader{
		reader:  r,
		limiter: l,
	}
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.limiter != nil {
		ctx := context.Background()
		if err := r.limiter.WaitN(ctx, n); err != nil {
			return 0, err
		}
	}
	return n, err
}

func setupLogging() {
	log.SetFlags(0)
	if quiet {
		log.SetOutput(io.Discard)
	} else {
		switch logLevel {
		case "error":
			log.SetOutput(os.Stderr)
		default:
			log.SetOutput(os.Stdout)
		}
	}
}

func loadCookies() {
	if cookiesFile == "" {
		return
	}

	file, err := os.Open(cookiesFile)
	if err != nil {
		log.Printf("Warning: Failed to load cookies - %v", err)
		return
	}
	defer file.Close()

	var cookies []*http.Cookie
	err = json.NewDecoder(file).Decode(&cookies)
	if err != nil {
		log.Printf("Warning: Invalid cookies file - %v", err)
		return
	}

	jar, _ := cookiejar.New(nil)
	for _, cookie := range cookies {
		parsedURL, err := url.Parse(cookie.Domain)
		if err != nil {
			continue
		}
		jar.SetCookies(parsedURL, []*http.Cookie{cookie})
	}

	http.DefaultClient.Jar = jar
}

func saveCookies() {
	if cookiesFile == "" || http.DefaultClient.Jar == nil {
		return
	}

	var cookies []*http.Cookie
	for urlStr := range downloadedFiles {
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}
		cookies = append(cookies, http.DefaultClient.Jar.Cookies(parsedURL)...)
	}

	file, err := os.Create(cookiesFile)
	if err != nil {
		log.Printf("Warning: Failed to save cookies - %v", err)
		return
	}
	defer file.Close()

	json.NewEncoder(file).Encode(cookies)
}

func download(parsedURL *url.URL, outputFile string, depth int) error {
	switch parsedURL.Scheme {
	case "http", "https":
		return downloadHTTP(parsedURL, outputFile, depth)
	case "ftp", "ftps":
		return downloadFTP(parsedURL)
	default:
		return fmt.Errorf("unsupported protocol: %s", parsedURL.Scheme)
	}
}

func createHTTPClient() *http.Client {
	proxy := http.ProxyFromEnvironment
	if proxyURL != "" {
		proxyURLParsed, _ := url.Parse(proxyURL)
		proxy = http.ProxyURL(proxyURLParsed)
	}

	transport := &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			DualStack: !preferIPv6,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			NextProtos:         []string{"h2", "http/1.1"},
		},
	}

	if http3Enabled {
		transport.TLSClientConfig.NextProtos = []string{"h3"}
	}

	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       timeout,
	}
}

func downloadHTTP(parsedURL *url.URL, outputFile string, depth int) error {
	client := createHTTPClient()
	var lastErr error

	for i := 0; i < retryCount; i++ {
		err := func() error {
			method := "GET"
			var body io.Reader

			if spiderMode {
				method = "HEAD"
			}

			if postData != "" || postFile != "" {
				method = "POST"
				var buf bytes.Buffer
				writer := multipart.NewWriter(&buf)

				if postData != "" {
					for _, param := range strings.Split(postData, "&") {
						kv := strings.SplitN(param, "=", 2)
						if len(kv) == 2 {
							writer.WriteField(kv[0], kv[1])
						}
					}
				}

				if postFile != "" {
					file, err := os.Open(postFile)
					if err != nil {
						return err
					}
					defer file.Close()

					part, err := writer.CreateFormFile("file", filepath.Base(postFile))
					if err != nil {
						return err
					}
					_, err = io.Copy(part, file)
					if err != nil {
						return err
					}
				}

				writer.Close()
				body = &buf

				req, err := http.NewRequest(method, parsedURL.String(), body)
				if err != nil {
					return err
				}

				req.Header.Set("User-Agent", userAgent)
				req.Header.Set("Content-Type", writer.FormDataContentType())

				if httpUser != "" || digestAuth {
					if digestAuth {
						authErr := handleDigestAuth(client, req)
						if authErr != nil {
							return authErr
						}
					} else {
						req.SetBasicAuth(httpUser, httpPass)
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				return processResponse(resp, parsedURL, outputFile, depth, client)
			} else {
				req, err := http.NewRequest(method, parsedURL.String(), body)
				if err != nil {
					return err
				}

				req.Header.Set("User-Agent", userAgent)

				if httpUser != "" {
					req.SetBasicAuth(httpUser, httpPass)
				}

				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				return processResponse(resp, parsedURL, outputFile, depth, client)
			}
		}()

		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(i) * time.Second)
	}

	return lastErr
}

func processResponse(resp *http.Response, parsedURL *url.URL, outputFile string, depth int, client *http.Client) error {
	if spiderMode {
		fmt.Printf("%d %s\n", resp.StatusCode, resp.Status)
		return nil
	}

	if mimeType != "" {
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, mimeType) {
			return fmt.Errorf("MIME type mismatch: %s", contentType)
		}
	}

	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return fmt.Errorf("server returned %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	finalOutput := generateOutputPath(parsedURL)
	if outputFile != "" {
		finalOutput = outputFile
	}

	if mirrorMode {
		os.MkdirAll(filepath.Dir(finalOutput), 0755)
	}

	file, err := os.OpenFile(finalOutput, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	contentLength := resp.ContentLength
	if continueFlag {
		fileInfo, _ := file.Stat()
		contentLength -= fileInfo.Size()
		resp.Request.Header.Set("Range", fmt.Sprintf("bytes=%d-", fileInfo.Size()))
	}

	var wg sync.WaitGroup
	chunkSize := contentLength / int64(parallel)
	start := int64(0)
	errChan := make(chan error, parallel)
	doneChan := make(chan struct{})

	if !quiet && !spiderMode {
		go printProgress(doneChan, contentLength, finalOutput)
	}

	for i := 0; i < parallel; i++ {
		end := start + chunkSize
		if i == parallel-1 {
			end = contentLength
		}

		wg.Add(1)
		go func(start, end int64) {
			defer wg.Done()
			err := downloadPart(parsedURL.String(), file, start, end, client)
			if err != nil {
				errChan <- err
			}
		}(start, end)

		start = end + 1
	}

	go func() {
		wg.Wait()
		close(errChan)
		close(doneChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	if convertLinks && !spiderMode {
		content, _ := os.ReadFile(finalOutput)
		doc, _ := html.Parse(bytes.NewReader(content))
		rewriteLinks(doc, parsedURL)
		os.WriteFile(finalOutput, []byte(renderHTML(doc)), 0644)
	}

	if mirrorMode {
		modTime, _ := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
		os.Chtimes(finalOutput, modTime, modTime)
	}

	if checksum != "" {
		err := verifyChecksum(finalOutput)
		if err != nil {
			return err
		}
	}

	if recursive && !spiderMode {
		return downloadRecursive(parsedURL, finalOutput, depth-1, client)
	}

	return nil
}

func printProgress(doneChan chan struct{}, total int64, filename string) {
	start := time.Now()
	width, _, _ := terminal.GetSize(0)

	for {
		select {
		case <-doneChan:
			fmt.Printf("\r%s\n", strings.Repeat(" ", width))
			return
		default:
			fileInfo, _ := os.Stat(filename)
			downloaded := fileInfo.Size()
			percent := float64(downloaded) / float64(total) * 100
			speed := float64(downloaded) / time.Since(start).Seconds() / 1e6

			if speed == 0 {
				continue
			}

			etaSecs := float64(total-downloaded) / (speed * 1e6)
			eta := time.Duration(etaSecs) * time.Second

			barWidth := width - 50
			progress := int(percent / 100 * float64(barWidth))
			bar := fmt.Sprintf("[%s%s] %.1f%% | %.2f MB/s | ETA: %s",
				strings.Repeat("=", progress),
				strings.Repeat(" ", barWidth-progress),
				percent,
				speed,
				eta.Truncate(time.Second),
			)

			fmt.Printf("\r%s", bar)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func verifyChecksum(filename string) error {
	parts := strings.SplitN(checksum, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid checksum format")
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var hasher interface {
		io.Writer
		Sum([]byte) []byte
	}

	switch parts[0] {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	default:
		return fmt.Errorf("unsupported hash type")
	}

	io.Copy(hasher, file)
	actual := hex.EncodeToString(hasher.(interface{ Sum([]byte) []byte }).Sum(nil))
	if actual != parts[1] {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", parts[1], actual)
	}
	return nil
}

func downloadPart(url string, file *os.File, start, end int64, client *http.Client) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	file.Seek(start, 0)
	_, err = io.Copy(file, resp.Body)
	return err
}

func downloadRecursive(baseUrl *url.URL, outputFile string, depth int, client *http.Client) error {
	content, err := os.ReadFile(outputFile)
	if err != nil {
		return err
	}

	baseNode, err := html.Parse(bytes.NewReader(content))
	if err != nil {
		return err
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.DataAtom == atom.Base {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					baseHref = attr.Val
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(baseNode)

	baseURL, _ := url.Parse(baseHref)
	if baseURL != nil {
		baseURL = baseUrl.ResolveReference(baseURL)
	} else {
		baseURL = baseUrl
	}

	links := extractLinks(baseNode)
	var wg sync.WaitGroup
	errChan := make(chan error, len(links))

	allowedDomains := strings.Split(domains, ",")
	acceptExts := strings.Split(acceptExt, ",")
	rejectExts := strings.Split(rejectExt, ",")

	for _, link := range links {
		absURL, err := url.Parse(link)
		if err != nil {
			continue
		}
		absURL = baseURL.ResolveReference(absURL)

		if !shouldDownload(absURL, baseUrl, allowedDomains, acceptExts, rejectExts, spanHosts, relativeOnly) {
			continue
		}

		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			parsedURL, parseErr := url.Parse(urlStr)
			if parseErr != nil {
				errChan <- parseErr
				return
			}
			downloadErr := download(parsedURL, "", depth-1)
			if downloadErr != nil {
				errChan <- downloadErr
			}
		}(absURL.String())
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	var lastErr error
	for err := range errChan {
		lastErr = err
	}

	return lastErr
}

func extractLinks(doc *html.Node) []string {
	var links []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.DataAtom == atom.A {
			for _, a := range n.Attr {
				if a.Key == "href" {
					links = append(links, a.Val)
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return links
}

func resolveURL(base *url.URL, rel string) *url.URL {
	relURL, _ := url.Parse(rel)
	return base.ResolveReference(relURL)
}

func shouldDownload(absURL, baseURL *url.URL, allowedDomains, acceptExts, rejectExts []string, spanHosts, relativeOnly bool) bool {
	downloadLock.Lock()
	defer downloadLock.Unlock()

	if downloadedFiles[absURL.String()] {
		return false
	}

	if !spanHosts && absURL.Host != baseURL.Host {
		return false
	}

	if len(allowedDomains) > 0 {
		found := false
		for _, domain := range allowedDomains {
			if domain == "" {
				continue
			}
			if strings.HasSuffix(absURL.Host, domain) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if relativeOnly && absURL.Host != baseURL.Host {
		return false
	}

	ext := filepath.Ext(absURL.Path)
	if len(acceptExts) > 0 {
		found := false
		for _, e := range acceptExts {
			if e == "" {
				continue
			}
			if strings.HasSuffix(ext, "."+e) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rejectExts) > 0 {
		for _, e := range rejectExts {
			if e == "" {
				continue
			}
			if strings.HasSuffix(ext, "."+e) {
				return false
			}
		}
	}

	downloadedFiles[absURL.String()] = true
	return true
}

func handleDigestAuth(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		return nil
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	params := parseDigestParams(authHeader)
	ha1 := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", httpUser, params["realm"], httpPass)))
	ha2 := md5.Sum([]byte(fmt.Sprintf("%s:%s", req.Method, req.URL.Path)))
	nonceCount := "00000001"
	cnonceBytes := make([]byte, 8)
	rand.Read(cnonceBytes)
	cnonce := hex.EncodeToString(cnonceBytes)
	response := md5.Sum([]byte(fmt.Sprintf("%x:%s:%s:%s:%s:%x", ha1, params["nonce"], nonceCount, cnonce, "auth", ha2)))

	authValue := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=auth, nc=%s, cnonce="%s", response="%x"`,
		httpUser, params["realm"], params["nonce"], req.URL.Path, nonceCount, cnonce, response)

	req.Header.Set("Authorization", authValue)
	return nil
}

func parseDigestParams(header string) map[string]string {
	params := make(map[string]string)
	header = strings.TrimPrefix(header, "Digest ")
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.Trim(kv[1], `"`)
			params[key] = value
		}
	}
	return params
}

// --- FTP Wildcard Implementation Start ---
func downloadFTP(parsedURL *url.URL) error {
	path := parsedURL.Path
	if strings.ContainsAny(path, "*?") {
		return downloadFTPWildcard(parsedURL)
	}
	return downloadSingleFTPFile(parsedURL)
}

func downloadFTPWildcard(parsedURL *url.URL) error {
	tp, err := ftpConnect(parsedURL)
	if err != nil {
		return err
	}
	defer tp.Close()

	files, err := listFTPFiles(tp, parsedURL.Path)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return fmt.Errorf("no files matching pattern: %s", parsedURL.Path)
	}

	for _, file := range files {
		fileURL := *parsedURL
		fileURL.Path = file
		if err := downloadSingleFTPFile(&fileURL); err != nil {
			return err
		}
	}
	return nil
}

func ftpConnect(parsedURL *url.URL) (*textproto.Conn, error) {
	config := &tls.Config{
		ServerName:         parsedURL.Hostname(),
		InsecureSkipVerify: false,
	}

	var controlConn net.Conn
	var err error

	switch parsedURL.Scheme {
	case "ftps":
		controlConn, err = tls.Dial("tcp", parsedURL.Host+":21", config)
	default:
		controlConn, err = net.Dial("tcp", parsedURL.Host+":21")
	}
	if err != nil {
		return nil, err
	}

	tp := textproto.NewConn(controlConn)
	_, _, err = tp.ReadResponse(220)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("FTP connection failed: %v", err)
	}

	user := ftpUser
	if user == "" {
		user = "anonymous"
	}
	pass := ftpPass
	if user == "anonymous" && pass == "" {
		pass = "goget@example.com"
	}

	id, err := tp.Cmd("USER %s", user)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("USER command failed: %v", err)
	}
	_, _, err = tp.ReadResponse(int(id))
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("FTP login failed: %v", err)
	}

	id, err = tp.Cmd("PASS %s", pass)
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("PASS command failed: %v", err)
	}
	_, _, err = tp.ReadResponse(int(id))
	if err != nil {
		tp.Close()
		return nil, fmt.Errorf("FTP authentication failed: %v", err)
	}

	return tp, nil
}

func listFTPFiles(tp *textproto.Conn, path string) ([]string, error) {
	dir, pattern := filepath.Split(path)
	if dir == "" {
		dir = "."
	}

	id, err := tp.Cmd("CWD %s", dir)
	if err != nil {
		return nil, fmt.Errorf("CWD failed: %v", err)
	}
	if _, _, err := tp.ReadResponse(int(id)); err != nil {
		return nil, fmt.Errorf("CWD failed: %v", err)
	}

	id, err = tp.Cmd("NLST")
	if err != nil {
		return nil, fmt.Errorf("NLST failed: %v", err)
	}
	code, msg, err := tp.ReadResponse(int(id))
	if err != nil || code != 226 {
		return nil, fmt.Errorf("NLST failed: %d %s", code, msg)
	}

	files := strings.Split(strings.TrimSpace(msg), "\n")
	var matchedFiles []string
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		if matchWildcard(pattern, filepath.Base(file)) {
			matchedFiles = append(matchedFiles, filepath.Join(dir, file))
		}
	}
	return matchedFiles, nil
}

func downloadSingleFTPFile(parsedURL *url.URL) error {
	tp, err := ftpConnect(parsedURL)
	if err != nil {
		return err
	}
	defer tp.Close()

	id, err := tp.Cmd("TYPE I")
	if err != nil {
		return fmt.Errorf("TYPE I failed: %v", err)
	}
	if _, _, err := tp.ReadResponse(int(id)); err != nil {
		return fmt.Errorf("TYPE I failed: %v", err)
	}

	var dataConn net.Conn
	if preferIPv6 || parsedURL.Scheme == "ftps" {
		id, err = tp.Cmd("EPSV")
		if err != nil {
			return fmt.Errorf("EPSV failed: %v", err)
		}
		code, msg, err := tp.ReadResponse(int(id))
		if err != nil {
			return fmt.Errorf("EPSV failed: %v", err)
		}
		if code != 229 {
			return fmt.Errorf("EPSV failed: %s", msg)
		}
		dataAddr, err := parseEPSV(parsedURL, msg)
		if err != nil {
			return err
		}
		dataConn, err = tls.Dial("tcp", dataAddr, &tls.Config{InsecureSkipVerify: false})
	} else {
		id, err = tp.Cmd("PASV")
		if err != nil {
			return fmt.Errorf("PASV failed: %v", err)
		}
		code, msg, err := tp.ReadResponse(int(id))
		if err != nil {
			return fmt.Errorf("PASV failed: %v", err)
		}
		if code != 227 {
			return fmt.Errorf("PASV failed: %s", msg)
		}
		dataAddr, err := parsePASV(msg)
		if err != nil {
			return err
		}
		dataConn, err = net.Dial("tcp", dataAddr)
	}
	if err != nil {
		return err
	}
	defer dataConn.Close()

	id, err = tp.Cmd("RETR %s", parsedURL.Path)
	if err != nil {
		return fmt.Errorf("RETR failed: %v", err)
	}
	if _, _, err := tp.ReadResponse(150); err != nil {
		return fmt.Errorf("RETR failed: %v", err)
	}

	outputPath := generateOutputPath(parsedURL)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, dataConn); err != nil {
		return err
	}

	_, _, err = tp.ReadResponse(226)
	return err
}

func parseEPSV(parsedURL *url.URL, msg string) (string, error) {
	re := regexp.MustCompile(`\|\|\|(\d+)\|`)
	matches := re.FindStringSubmatch(msg)
	if len(matches) != 2 {
		return "", fmt.Errorf("invalid EPSV response")
	}

	port, _ := strconv.Atoi(matches[1])
	return fmt.Sprintf("[%s]:%d", parsedURL.Hostname(), port), nil
}

func parsePASV(msg string) (string, error) {
	re := regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)
	matches := re.FindStringSubmatch(msg)
	if len(matches) != 7 {
		return "", fmt.Errorf("invalid PASV response")
	}

	ip := fmt.Sprintf("%s.%s.%s.%s", matches[1], matches[2], matches[3], matches[4])
	port := strconv.Itoa(int((atoi(matches[5]) << 8) + atoi(matches[6])))
	return fmt.Sprintf("%s:%s", ip, port), nil
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func matchWildcard(pattern, name string) bool {
	regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
	regexPattern = strings.ReplaceAll(regexPattern, "\\?", ".")
	matched, _ := regexp.MatchString(regexPattern, name)
	return matched
}

// --- FTP Wildcard Implementation End ---

func generateOutputPath(parsedURL *url.URL) string {
	path := parsedURL.Path
	if path == "" || path == "/" {
		path = "/index.html"
	}

	if mirrorMode {
		host := parsedURL.Hostname()
		if parsedURL.Port() != "" {
			host += ":" + parsedURL.Port()
		}
		return filepath.Join("downloads", host, path)
	}

	return filepath.Base(path)
}

func rewriteLinks(doc *html.Node, baseUrl *url.URL) {
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.A, atom.Link, atom.Script, atom.Img:
				for i, attr := range n.Attr {
					if attr.Key == "href" || attr.Key == "src" {
						absURL := resolveURL(baseUrl, attr.Val)
						n.Attr[i].Val = absURL.String()
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}

func renderHTML(n *html.Node) string {
	var buf bytes.Buffer
	html.Render(&buf, n)
	return buf.String()
}
