package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const testPropsJSON = `{"addition_date":1770257484,"name":"Real.Name","total_size":1000,"pieces_num":10}`

func TestFetchTorrentMeta_CarriesAdditionDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testPropsJSON))
	}))
	defer srv.Close()

	meta, err := newQBClient(srv.URL, "", "", time.Second).FetchTorrentMeta("abc")
	if err != nil {
		t.Fatalf("FetchTorrentMeta: %v", err)
	}
	if !meta.AddedAt.Equal(time.Unix(1770257484, 0)) {
		t.Errorf("AddedAt = %v, want %v", meta.AddedAt, time.Unix(1770257484, 0))
	}
	if meta.Name != "Real.Name" || meta.Size != 1000 || meta.PieceCount != 10 {
		t.Errorf("meta = %+v", meta)
	}
}

// TestFetchTorrentMeta_LoginWaitsForAPI: credentials configured and the WebUI not
// up at daemon start must not disable the client for the life of the process.
func TestFetchTorrentMeta_LoginWaitsForAPI(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/api/v2/auth/login" {
			w.Write([]byte("Ok."))
			return
		}
		w.Write([]byte(testPropsJSON))
	}))
	defer srv.Close()

	q := newQBClient(srv.URL, "user", "pass", time.Second)
	if _, err := q.FetchTorrentMeta("abc"); err == nil {
		t.Fatal("expected an error while the API is down")
	}

	up.Store(true)
	meta, err := q.FetchTorrentMeta("abc")
	if err != nil {
		t.Fatalf("FetchTorrentMeta after API came up: %v", err)
	}
	if meta.Name != "Real.Name" {
		t.Errorf("name = %q, want Real.Name", meta.Name)
	}
}

// TestFetchTorrentMeta_HungAPIReturns: a WebUI that accepts and never answers
// must not stall the resolver.
func TestFetchTorrentMeta_HungAPIReturns(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	q := newQBClient(srv.URL, "", "", 100*time.Millisecond)
	errCh := make(chan error, 1)
	go func() {
		_, err := q.FetchTorrentMeta("abc")
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected an error from a hung API")
		}
	case <-time.After(3 * time.Second):
		t.Error("FetchTorrentMeta still blocked 3s into a 100ms response timeout")
	}
}
