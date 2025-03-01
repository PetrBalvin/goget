// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const version = "1.0.0-preview"

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
	versionFlag     bool // Nová proměnná pro příznak --version
	downloadedFiles = make(map[string]bool)
	downloadLock    sync.Mutex
	baseHref        string
)

func init() {
	flag.StringVar(&urlFlag, "url", "", "URL to download")
	flag.StringVar(&output, "O", "", "Output file name")
	flag.BoolVar(&preferIPv6, "6", false, "Use IPv6 only")
	flag.BoolVar(&continueFlag, "c", false, "Continue getting a partially-downloaded file")
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
	flag.BoolVar(&versionFlag, "version", false, "Show version") // Registrace příznaku --version
	flag.Parse()
}

func main() {
	// Kontrola příznaku --version
	if versionFlag {
		fmt.Printf("goget version %s\n", version)
		os.Exit(0)
	}

	if urlFlag == "" {
		log.Fatal("Error: URL is required")
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
	case "ftp":
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
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       timeout,
	}

	return client
}

func downloadHTTP(parsedURL *url.URL, outputFile string, depth int) error {
	client := createHTTPClient()
	var lastErr error

	for i := 0; i < retryCount; i++ {
		err := func() error {
			req, _ := http.NewRequest("GET", parsedURL.String(), nil)
			req.Header.Set("User-Agent", userAgent)

			if httpUser != "" || digestAuth {
				if digestAuth {
					err := handleDigestAuth(client, req)
					if err != nil {
						return err
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

			if resp.StatusCode != 200 && resp.StatusCode != 206 {
				return fmt.Errorf("server returned %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
			}

			finalOutput := outputFile
			if finalOutput == "" {
				finalOutput = generateOutputFileName(parsedURL)
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
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-", fileInfo.Size()))
			}

			var wg sync.WaitGroup
			chunkSize := contentLength / int64(parallel)
			start := int64(0)
			errChan := make(chan error, parallel)

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
			}()

			for err := range errChan {
				if err != nil {
					return err
				}
			}

			if recursive {
				return downloadRecursive(parsedURL, finalOutput, depth-1, client)
			}

			return nil
		}()

		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(i) * time.Second)
	}

	return lastErr
}

func generateOutputFileName(parsedURL *url.URL) string {
	path := parsedURL.Path
	if path == "" || path == "/" {
		return "index.html"
	}

	base := filepath.Base(path)
	if base == "" || base == "." || base == "/" {
		return "index.html"
	}

	return base
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

func downloadPart(url string, file *os.File, start, end int64, client *http.Client) error {
	req, _ := http.NewRequest("GET", url, nil)
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

	var baseHref string
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
			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				errChan <- err
				return
			}
			err = download(parsedURL, "", depth-1)
			if err != nil {
				errChan <- err
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

func downloadFTP(parsedURL *url.URL) error {
	conn, err := net.Dial("tcp", parsedURL.Host+":21")
	if err != nil {
		return err
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)
	defer tp.Close()

	code, msg, _ := tp.ReadResponse(220)
	if code != 220 {
		return fmt.Errorf("FTP connection failed: %s", msg)
	}

	user := ftpUser
	if user == "" {
		user = "anonymous"
	}
	pass := ftpPass
	if user == "anonymous" && pass == "" {
		pass = "goget@example.com"
	}

	tp.PrintfLine("USER %s", user)
	code, _, _ = tp.ReadResponse(331)
	if code != 331 && code != 230 {
		return fmt.Errorf("FTP login failed")
	}

	tp.PrintfLine("PASS %s", pass)
	code, _, _ = tp.ReadResponse(230)
	if code != 230 {
		return fmt.Errorf("FTP authentication failed")
	}

	tp.PrintfLine("TYPE I")
	code, _, _ = tp.ReadResponse(200)
	if code != 200 {
		return fmt.Errorf("FTP TYPE I failed")
	}

	tp.PrintfLine("PASV")
	code, msg, _ = tp.ReadResponse(227)
	if code != 227 {
		return fmt.Errorf("FTP PASV failed")
	}

	dataConn, err := parsePASV(msg)
	if err != nil {
		return err
	}

	tp.PrintfLine("LIST %s", parsedURL.Path)
	code, _, _ = tp.ReadResponse(150)
	if code != 150 {
		return fmt.Errorf("FTP LIST failed")
	}

	reader := bufio.NewReader(dataConn)
	scanner := bufio.NewScanner(reader)
	var files []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "d") {
			dirName := strings.Fields(line)[8]
			files = append(files, dirName+"/")
		} else {
			fileName := strings.Fields(line)[8]
			files = append(files, fileName)
		}
	}

	dataConn.Close()
	tp.ReadResponse(226)

	for _, file := range files {
		fileURL := *parsedURL
		fileURL.Path = filepath.Join(fileURL.Path, file)
		err := download(&fileURL, "", maxDepth-1)
		if err != nil {
			return err
		}
	}

	return nil
}

func parsePASV(msg string) (net.Conn, error) {
	re := regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)
	matches := re.FindStringSubmatch(msg)
	if len(matches) != 7 {
		return nil, fmt.Errorf("invalid PASV response")
	}

	ip := fmt.Sprintf("%s.%s.%s.%s", matches[1], matches[2], matches[3], matches[4])
	port := strconv.Itoa(int((atoi(matches[5]) << 8) + atoi(matches[6])))
	return net.Dial("tcp", ip+":"+port)
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
