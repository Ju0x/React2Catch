package main

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const (
	maxPerIP = 3
	maxConns = 200
)

var (
	slots = make(chan uint8, maxConns)

	mu      sync.Mutex
	ipConns = map[string]int{}
)

// Checking a global and a per-ip ratelimit to prevent the DoS attack surface
func allowRequest(ip string) bool {
	// --- Per-IP  ---
	mu.Lock()
	if ipConns[ip] >= maxPerIP {
		mu.Unlock()
		return false
	}
	ipConns[ip]++
	mu.Unlock()

	// --- Global limit ---
	select {
	case slots <- 1:
		return true
	default:
		releaseIP(ip)
		return false
	}
}

func releaseIP(ip string) {
	mu.Lock()
	defer mu.Unlock()

	ipConns[ip]--
	if ipConns[ip] <= 0 {
		delete(ipConns, ip)
	}
}

func tarpitHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var caughtTime time.Duration

	ip := normalizeIP(RealSource(r))

	w.Header().Set("Content-Type", "text/plain")

	if ip == "" {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}

	if !allowRequest(ip) {
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}
	defer func(ip string) {
		<-slots
		releaseIP(ip)
		log.Printf("Caught %s in tarpit for %s", ip, caughtTime)
	}(ip)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, err := w.Write([]byte("\n"))
			if err != nil {
				return
			}
			flusher.Flush()

			// Adding duration manually, so we get a better result of how long the (working) connection was there
			caughtTime += time.Since(start)

			// Using random delay, just in case
			time.Sleep(time.Duration(1000+rand.Intn(5000)) * time.Millisecond)
		}
	}

}
