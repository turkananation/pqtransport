// masque-go v0.6.0 CONNECT-UDP proxy. The certificate is loaded by
// this process. pqtransport is the client.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	bind := flag.String("b", "127.0.0.1:0", "UDP address")
	certFile := flag.String("c", "", "leaf PEM")
	keyFile := flag.String("k", "", "seed-only PKCS#8 PEM")
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: udp-proxy -b host:port -c cert.pem -k key.pem")
		os.Exit(64)
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fatal(err)
	}
	pc, err := net.ListenPacket("udp", *bind)
	if err != nil {
		fatal(err)
	}
	addr := pc.LocalAddr().String()
	template, err := uritemplate.New("https://" + addr + "/.well-known/masque/udp/{target_host}/{target_port}/")
	if err != nil {
		fatal(err)
	}
	proxy := masque.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			var perr *masque.ProxyRequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				log.Printf("parse %d %v", perr.HTTPStatus, err)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("parse %v", err)
			return
		}
		log.Printf("connect-udp target=%s", req.Target)
		if err := proxy.Proxy(w, req); err != nil {
			log.Printf("proxy %v", err)
		}
	})
	server := http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}),
		EnableDatagrams: true,
		Handler:         mux,
	}
	fmt.Printf("listening %s\n", addr)
	if err := server.Serve(pc); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "udp-proxy: %v\n", err)
	os.Exit(1)
}
