package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"defang.io/acme/aws/acm"
	"defang.io/acme/aws/alb"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var httpChallengeToken string
var updating atomic.Bool
var m *autocert.Manager

func main() {
	cache := &LoggingCache{cache: make(map[string][]byte)}
	m = &autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("dayifu.click"),
		Client: &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		},
	}

	m.HTTPHandler(nil) // enable http-01 challenge

	log.Printf("Start updating certificate")
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "dayifu.click", 
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, // Enforce ECDSA
	})
	if err != nil {
		log.Printf("Error getting certificate: %v", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	fmt.Printf("Certificate: %s\n", certPem)

	certArn := ""
	if len(os.Args) > 1 {
		certArn = os.Args[1]
	}

	if cert != nil {
		if err := acm.ImportCertificate(context.Background(), cert, certArn); err != nil {
			log.Printf("Error importing certificate: %v", err)
		}
	}

	log.Printf("Done")
}

type LoggingCache struct {
	cache map[string][]byte
}

func (c *LoggingCache) Get(ctx context.Context, key string) ([]byte, error) {
	log.Printf("Get %s\n", key)
	if key == "acme_account+key" {
		accKey, err := os.ReadFile("./" + key)
		if err != nil {
			log.Printf("Error deleting account key: %v", err)
		}
		if len(accKey) == 0 {
			return nil, autocert.ErrCacheMiss
		}
		return accKey, nil
	}
	v, ok := c.cache[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return v, nil
}

func (c *LoggingCache) Put(ctx context.Context, key string, data []byte) error {
	log.Printf("Put %s with value of %d bytes\n", key, len(data))
	if key == "acme_account+key" {
		err := os.WriteFile("./"+key, data, 0644)
		if err != nil {
			log.Printf("Error writing account key: %v", err)
			return err
		}
		return nil
	}
	if strings.HasSuffix(key, "+http-01") {
		log.Printf("Caching http challeng token: %s -> %s\n", key, string(data))
		httpChallengeToken = string(data)
		tokenPath := "/.well-known/acme-challenge/" + strings.TrimSuffix(key, "+http-01")
		listener, err := alb.GetHttpListener(ctx, alb.AlbArn)
		if err != nil {
			log.Printf("Error getting http listener: %v", err)
		}

		go func() {
			checkUrl := "http://dayifu.click" + tokenPath
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			for {
				resp, err := client.Get(checkUrl)
				if err != nil {
					log.Printf("Error checking token: %v", err)
				}
				body, err := io.ReadAll(resp.Body)
				log.Printf("Check token code %v, response: %s", resp.StatusCode, body)
				time.Sleep(500 * time.Millisecond)
			}
		}()

		if err := alb.AddListenerStaticRule(ctx, *listener.ListenerArn, tokenPath, httpChallengeToken); err != nil {
			log.Printf("Error adding listener static rule: %v", err)
		}
		log.Printf("Wait for rule to take effect")
		time.Sleep(20 * time.Second)
	}
	c.cache[key] = data
	return nil
}

func (c *LoggingCache) Delete(ctx context.Context, key string) error {
	log.Printf("Delete %s\n", key)
	if key == "acme_account+key" {
		err := os.Remove("./" + key)
		if err != nil {
			log.Printf("Error deleting account key: %v", err)
		}
		return nil
	}
	if strings.HasSuffix(key, "+http-01") {
		log.Printf("Deleting http challeng token: %s \n", key)
		tokenPath := "/.well-known/acme-challenge/" + strings.TrimSuffix(key, "+http-01")
		listener, err := alb.GetHttpListener(ctx, alb.AlbArn)
		if err != nil {
			log.Printf("Error getting http listener: %v", err)
		}
		alb.DeleteListenerStaticRule(ctx, *listener.ListenerArn, tokenPath)
	}
	delete(c.cache, key)
	return nil
}

func serveHttp() {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		// fmt.Fprintf(w, "Received acme http-01 challenge at: %s", r.PathValue("tokenpath"))
		log.Printf("Received acme http-01 challenge at: %s", r.URL.Path)
		if httpChallengeToken == "" {
			log.Printf("No http challenge token available")
		}
		log.Printf("Responding with http challenge token: %s", httpChallengeToken)
		fmt.Fprintf(w, "%s", httpChallengeToken)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request for %s, %v", r.URL.Path, time.Now())
		if updating.CompareAndSwap(false, true) {
			go func() {
				log.Printf("Start updating certificate")
				defer updating.Store(false)
				cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "dayifu.click", SupportedCurves: []tls.CurveID{tls.CurveP256}})
				if err != nil {
					log.Printf("Error getting certificate: %v", err)
				}
				if cert != nil {
					log.Printf("Obtained certificate: %+v", cert.Certificate)
				}
				log.Printf("Done handling request for %s, %v", r.URL.Path, time.Now())
			}()
		}
		fmt.Fprintf(w, "Hello, TLS user! Your config: %+v", r.TLS)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
