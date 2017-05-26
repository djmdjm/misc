package main

// RFC1035 DNS name compression.
//
// I wrote this because OpenBSD includes an older dhcpd that doesn't support
// an option for setting the DNS search order. Newer dhcpd include this as
// "option domain-search".
//
// This tool accepts one or more domain names and emits a hex string that may
// be used as a custom option to achieve the same result. E.g.
// "go run dnscompress.go example.com int.example.com"
// will produce "07:65:78:61:6d:70:6c:65:03:63:6f:6d:00:03:69:6e:74:c0:00"
//
// This can then be used in dhcpd.conf as:
// option option-119 07:65:78:61:6d:70:6c:65:03:63:6f:6d:00:03:69:6e:74:c0:00;
//
// NB. This tool does approximately no input validation and doesn't handle
// international domain names at all.

// Damien Miller 2017/05

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var debug = flag.Bool("debug", false, "verbose debugging")

// DNSCompressor represents a set of compressed DNS names.
type DNSCompressor struct {
	suffixmap map[string]int
	buf       bytes.Buffer
}

// NewDNSCompressor prepares a new, empty DNSCompressor.
func NewDNSCompressor() *DNSCompressor {
	return &DNSCompressor{suffixmap: map[string]int{}}
}

// AddName appends a name to a compressed name set.
func (dc *DNSCompressor) AddName(name string) error {
	c := strings.Split(name, ".")
	for i := 0; i < len(c); i++ {
		if len(c[i]) > 63 {
			return fmt.Errorf("Component %v of name %v too long", i, name)
		}
		j := strings.Join(c[i:], ".")
		offset, ok := dc.suffixmap[j]
		if *debug {
			fmt.Printf("name %v: %v %v %v %v %v %v\n", name, dc.buf.Len(), i, c[i], j, offset, ok)
		}
		if ok {
			// Suffix already exists, emit pointer to it.
			dc.buf.WriteByte(0xc0 | byte(((offset >> 8) & 0xff)))
			dc.buf.WriteByte(byte(offset) & 0xff)
			return nil
		}
		// Record suffix in map.
		dc.suffixmap[j] = dc.buf.Len()
		// Emit component length.
		dc.buf.WriteByte(byte(len(c[i])))
		// Emit component.
		dc.buf.Write([]byte(c[i]))
	}
	// Complete name written. Terminate with 0x00.
	dc.buf.WriteByte(0x00)
	return nil
}

// Dump writes a hex dump of the contents of a DNSCompression (mostly for
// debugging).
func (dc *DNSCompressor) Dump(w io.Writer) {
	dumper := hex.Dumper(w)
	dumper.Write(dc.buf.Bytes())
	dumper.Close()
}

// Hex writes a colon-separated hex representation of the set of compressed
// domain names in a format compatible with ISC dhcpd's hex options.
func (dc *DNSCompressor) Hex() (string, error) {
	if dc.buf.Len() > 0x3fff {
		return "", fmt.Errorf("Output is too large")
	}
	bbytes := dc.buf.Bytes()
	var ret string
	for i, b := range bbytes {
		if i > 0 {
			ret = ret + ":"
		}
		ret = ret + fmt.Sprintf("%02x", b)
	}
	return ret, nil
}

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: compress-names name [name...]")
		os.Exit(1)
	}
	dc := NewDNSCompressor()
	for _, name := range flag.Args() {
		err := dc.AddName(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *debug {
		dc.Dump(os.Stdout)
	}
	s, err := dc.Hex()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(s)
}
