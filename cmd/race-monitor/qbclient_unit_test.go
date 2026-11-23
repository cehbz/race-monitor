package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestFetchTorrentMeta_ConcurrentCallers: each pending start classifies in its
// own goroutine, so concurrent first calls share one client. Run with -race.
func TestFetchTorrentMeta_ConcurrentCallers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auth/login" {
			w.Write([]byte("Ok."))
			return
		}
		w.Write([]byte(testPropsJSON))
	}))
	defer srv.Close()

	q := newQBClient(srv.URL, "user", "pass", time.Second)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if meta, err := q.FetchTorrentMeta("abc"); err != nil || meta.Name != "Real.Name" {
				t.Errorf("FetchTorrentMeta = %+v, %v", meta, err)
			}
		}()
	}
	wg.Wait()
}

// TestFetchTorrentMeta_HungLoginDoesNotQueueCallers: against a WebUI that never
// answers a login, each concurrent caller gives up after about one response
// timeout, not after the logins queued ahead of it.
func TestFetchTorrentMeta_HungLoginDoesNotQueueCallers(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	const timeout = 100 * time.Millisecond
	const callers = 5
	q := newQBClient(srv.URL, "user", "pass", timeout)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			_, err := q.FetchTorrentMeta("abc")
			if err == nil {
				t.Error("expected an error from a hung login")
			}
			if took := time.Since(start); took > 3*timeout {
				t.Errorf("call returned after %v, want about %v", took, timeout)
			}
		}()
	}
	wg.Wait()
}
