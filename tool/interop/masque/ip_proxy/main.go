// connect-ip-go v0.6.0 CONNECT-IP proxy. Assigns 192.0.2.11/32,
// advertises every IPv4 address, and echoes one packet whose
// destination is that assignment. pqtransport is the client.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	bind := flag.String("b", "127.0.0.1:0", "UDP address")
	certFile := flag.String("c", "", "leaf PEM")
	keyFile := flag.String("k", "", "seed-only PKCS#8 PEM")
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: ip-proxy -b host:port -c cert.pem -k key.pem")
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
	template, err := uritemplate.New("https://" + addr + "/.well-known/masque/ip/*/*/")
	if err != nil {
		fatal(err)
	}
	proxy := connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := connectip.ParseProxyRequest(r, template); err != nil {
			var perr *connectip.ProxyRequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				log.Printf("parse %d %v", perr.HTTPStatus, err)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("parse %v", err)
			return
		}
		conn, err := proxy.Proxy(w, nil)
		if err != nil {
			log.Printf("proxy %v", err)
			return
		}
		defer conn.Close()
		if err := conn.AssignAddresses([]netip.Prefix{
			netip.MustParsePrefix("192.0.2.11/32"),
		}); err != nil {
			log.Printf("assign %v", err)
			return
		}
		if err := conn.AdvertiseRoute([]connectip.IPRoute{{
			StartIP:    netip.MustParseAddr("0.0.0.0"),
			EndIP:      netip.MustParseAddr("255.255.255.255"),
			IPProtocol: 0,
		}}); err != nil {
			log.Printf("route %v", err)
			return
		}
		buf := make([]byte, 1500)
		n, err := conn.ReadPacket(buf)
		if err != nil {
			log.Printf("read %v", err)
			return
		}
		if n < 20 {
			log.Printf("short %d", n)
			return
		}
		log.Printf(
			"ip-got n=%d src=%d.%d.%d.%d dst=%d.%d.%d.%d proto=%d",
			n, buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[9],
		)
		reply := swap(buf[:n])
		icmp, err := conn.WritePacket(reply)
		if err != nil || icmp != nil {
			log.Printf("write err=%v icmp=%d", err, len(icmp))
			return
		}
		log.Printf("ip-echo n=%d", n)
		time.Sleep(2 * time.Second)
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

func swap(packet []byte) []byte {
	out := append([]byte(nil), packet...)
	var src [4]byte
	copy(src[:], out[12:16])
	copy(out[12:16], out[16:20])
	copy(out[16:20], src[:])
	out[10], out[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(out[i])<<8 | uint32(out[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(out[10:12], ^uint16(sum))
	return out
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "ip-proxy: %v\n", err)
	os.Exit(1)
}
