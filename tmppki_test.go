package tmppki

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestGeneratePKI(t *testing.T) {
	tmppki, err := NewTemporaryPKI(RSA, S128, nil)
	if err != nil {
		t.Fatal(err)
	}
	remover, err := tmppki.GeneratePKI()
	if err != nil {
		t.Fatal(err)
	}
	defer remover()
	certFile, err := os.Open(tmppki.CertPath())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(os.Stdout, certFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestListenAndServeTLS(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello World!")
	})
	server := &http.Server{
		Addr:    ":" + "9080",
		Handler: handler,
	}

	tmppki, err := NewTemporaryPKI(RSA, S128, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		ctx := context.Background()
		time.Sleep(time.Second * 3)

		err := server.Shutdown(ctx)
		switch {
		case err == http.ErrServerClosed:
			return
		case err != nil:
			t.Log(err)
			t.Fail()
		}
	}()

	err = tmppki.ListenAndServeTLS(server)
	if err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
