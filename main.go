package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var (
	addr    string
	trusted string
	output  string

	headerIndicator *regexp.Regexp
	bodyIndicator   *regexp.Regexp
)

func regexCompile(regex string) *regexp.Regexp {
	compiled, err := regexp.Compile(regex)

	if err != nil {
		log.Fatal(err)
	}
	return compiled
}

func init() {
	flag.StringVar(&addr, "addr", ":8080", "Host value (e.g. :8080, localhost:1337, 0.0.0.0:1234)")
	flag.StringVar(&trusted, "trusted", "", "Trusted proxies (IPs seperated by comma, e.g. --trusted 127.0.0.1,::1)")
	flag.StringVar(&output, "output", "catches.jsonl", "Output file for the logs")
	flag.Parse()

	if len(trusted) > 0 {
		trustedProxies = strings.Split(trusted, ",")
	}

	headerIndicator = regexCompile(`next-action|x-action-redirect|rsc-action-id`)
	bodyIndicator = regexCompile(`_prefix.*execSync\s*\(`)
}

type Matches struct {
	Header bool `json:"header"`
	Body   bool `json:"body"`
}

// Checks for the regex indicators, used to determine if the request data should be logged
func checkIndicators(w http.ResponseWriter, r *http.Request) (Matches, string, error) {
	matches := Matches{false, false}

	for headerName := range r.Header {
		if headerIndicator.MatchString(strings.ToLower(headerName)) {
			matches.Header = true
			break
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return matches, "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("[Error] checkIndicators: failed to close body - %v", err)
		}
	}(r.Body)

	if bodyIndicator.Match(body) {
		matches.Body = true
	}

	return matches, string(body), err
}

func main() {
	logger, err := NewLogger(output)

	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			matches, body, err := checkIndicators(w, r)

			if err != nil {
				log.Printf("[Error] checkIndicators: %v\n", err)
				return
			}

			if matches.Body && matches.Header {
				catch := Catch{
					Source:  RealSource(r),
					Host:    r.Host,
					Path:    r.URL.Path,
					Method:  r.Method,
					Headers: convertHeaders(r.Header),
					Body:    body,
				}

				logger.LogCatch(catch)
			}
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("500 Internal Server Error"))
		if err != nil {
			log.Printf("[Error] failed to write response: %v", err)
		}
	})

	log.Printf("React2Catch - Running on %s\n", addr)
	trusted = strings.Join(trustedProxies, ", ")
	if len(trusted) == 0 {
		log.Print("You do not trust any proxies. If React2Catch is running behind a proxy, it could lead to problems. Use --trusted to define trusted IPs.")
	} else {
		log.Printf("(!) Trusted proxies: %s", trusted)
	}
	log.Printf("Storing logs to %s\n", output)

	log.Fatal(http.ListenAndServe(addr, handler))
}
