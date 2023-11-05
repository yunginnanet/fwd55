package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

func main() {
	_, _ = os.Stdout.WriteString(string(net.ParseIP("127.0.0.1").To4()))
	_, _ = os.Stdout.Write([]byte{'\n'})
	serve()
}

type writer struct {
	write func(p []byte) (n int, err error)
}

func (w writer) Write(p []byte) (n int, err error) {
	return w.write(p)
}

func fmtHex(b []byte) string {
	s := strings.Builder{}
	s.WriteString("{")
	for i := range b {
		s.WriteString("0x")
		s.WriteString(hex.EncodeToString([]byte{b[i]}))
		if i < len(b)-1 {
			s.WriteString(", ")
		}
	}
	s.WriteString("}")
	return s.String()
}

const (
	red         = "\033[31m"
	yellow      = "\033[33m"
	orange      = "\033[38;5;208m"
	purple      = "\033[35m"
	blue        = "\033[34m"
	green       = "\033[32m"
	gray        = "\033[90m"
	reset       = "\033[0m"
	errPrefix   = red + "(ABORT) "
	warnPrefix  = orange + "(WARN!️️) " + reset
	startPrefix = green + "(START) " + reset
	closePrefix = red + "(CLOSE) " + reset
	infoPrefix  = gray + "(DEBUG️) " + reset
	writePrefix = yellow + "(W--->)" + reset
	readPrefix  = purple + "(<---R)" + reset
	finPrefix   = green + "(FINAL) " + reset
)

func handle(c net.Conn) {
	log := func(s string, isErr ...string) {
		dest := os.Stderr
		prefix := "[" + c.RemoteAddr().String() + "]\t"
		if len(isErr) > 0 && len(isErr[0]) > 0 {
			prefix = prefix[:len(prefix)-1]
			prefix += isErr[0]
		}
		_, _ = dest.Write([]byte(prefix))
		_, _ = dest.Write([]byte{byte('\t')})
		_, _ = dest.Write([]byte(s))
		if len(isErr) != 1 || isErr[0] != "" {
			_, _ = dest.Write([]byte{byte('\n')})
		}
		_, _ = dest.Write([]byte(reset))
	}

	var finished = false

	log0 := func(s string) {
		log(s, infoPrefix)
	}

	logRead := func(s string) {
		log(s, readPrefix)
	}

	logWrite := func(s string) {
		log("write: "+s, writePrefix)
	}

	log1 := func(s string) {
		log(s, errPrefix)
	}

	log2 := func(s string) {
		log(s, warnPrefix)
	}

	logFin := func(s string) {
		if finished {
			log(s, finPrefix)
		} else {
			log(s, closePrefix)
		}
	}

	logWriter := writer{write: func(p []byte) (n int, err error) {
		log(string(p))
		return len(p), nil
	}}

	log("connected", startPrefix)

	defer logFin("connection closed")

	log("reading 2 bytes of protocol negotiation data:")

	buf := make([]byte, 2)
	var r int
	var e error
	r, e = c.Read(buf)
	if e != nil {
		log1(e.Error())
		return
	}

	enc := hex.Dumper(logWriter)

	dump := func(buf []byte) {
		log0("dumping buffer:")
		_, _ = enc.Write(buf)
	}

	if r < 2 {
		log1("short read:")
		dump(buf[:r])
		_ = c.Close()
		return
	}

	if buf[0] != 0x05 {
		log1("bad version")
		dump(buf)
		_ = c.Close()
		return
	}

	logRead("SOCKS version: " + green + "5" + reset)

	numMethods := int(buf[1])
	if numMethods < 1 {
		log1("no methods")
		dump(buf)
		_ = c.Close()
		return
	}
	if numMethods > 255 {
		log1("too many methods (>255)")
		dump(buf)
		_ = c.Close()
		return
	}

	head := 1

	if buf[head] > 1 {
		log("more than one method (" + strconv.Itoa(int(buf[1])) + "), expanding buffer...")
		buf = append(buf, make([]byte, numMethods)...)
	}

	var authMethods = map[string]bool{
		"supports auth anonymous: ": false,
		"supports auth gssapi: ":    false,
		"supports auth user/pass: ": false,
	}

	updateAuthMethods := func(b byte) {
		logRead("\tauth method byte += " + blue + "0x" + hex.EncodeToString([]byte{b}) +
			reset + gray + " (int: " + strconv.Itoa(int(b)) + ")" + reset)
		switch {
		case b > 0x02:
			switch {
			case b > 0x02 && b < 0x7f:
				log2("iana assigned auth method used by client: " + strconv.Itoa(int(b)))
			case b > 0x7f && b < 0xfe:
				log2("reserved auth method used by client: " + strconv.Itoa(int(b)))
			case b == 0xff:
				log2("no acceptable auth methods (0xff) sent by client")
			default:
				log2("unknown auth method: " + strconv.Itoa(int(b)))
			}
		default:
			switch b {
			case 0x00:
				authMethods["supports auth anonymous: "] = true
			case 0x01:
				authMethods["supports auth gssapi: "] = true
			case 0x02:
				authMethods["supports auth user/pass: "] = true
			default:
				log2("unknown auth method: " + strconv.Itoa(int(b)))
			}
		}
	}

	printAuthMethods := func() {
		hdr := "--- client auth methods offered ---"
		log("\t" + hdr)
		var res = "N/A"
		for k, v := range authMethods {
			res = red + strconv.FormatBool(v) + reset
			if v {
				res = green + strconv.FormatBool(v) + reset
			}
			log0("\t" + k + res)
		}
		log("\t" + strings.Repeat("-", len(hdr)))
	}

	miniBuf := make([]byte, 1)
	oldHead := head + 1
	for head++; head-oldHead < numMethods; head++ {
		var e error
		if r, e = c.Read(miniBuf); e != nil {
			println(e.Error())
			_ = c.Close()
			return
		}
		if r < 1 {
			println("short read")
			_ = c.Close()
			return
		}
		updateAuthMethods(miniBuf[0])
		copy(buf[head:], miniBuf)
		miniBuf = slices.Delete(miniBuf, 0, 0)
	}

	printAuthMethods()

	if !authMethods["supports auth anonymous: "] {
		log1("does not support anonymous auth")
		// 0xff no acceptable auth methods
		logWrite(red + "0xff (no acceptable auth methods)" + reset)
		_, _ = c.Write([]byte{0x05, 0xff})
		_ = c.Close()
		return
	}

	logWrite(green + "0x00 (auth method good, go ahead)" + reset)

	written, e := c.Write([]byte{0x05, 0x00})
	if e != nil {
		log1(e.Error())
		_ = c.Close()
		return
	}

	if written != 2 {
		log1("short write")
		_ = c.Close()
		return
	}

	log("reading 10 bytes of request data...")

	buf = append(buf, make([]byte, 10)...)

	r, e = c.Read(buf[head:])

	if e != nil {
		log1(e.Error())
		_ = c.Close()
		return
	}

	if r < 10 {
		log1("short read")
		dump(buf[:r])
		_ = c.Close()
		return
	}

	if buf[head] != 0x05 {
		log1("bad version")
		dump(buf)
		_ = c.Close()
		return
	}

	head++

	if buf[head] != 0x01 {
		log1("bad command")
		dump(buf)
		_ = c.Close()
		return
	}

	logRead("\tcommand: " + blue + "connect" + reset)

	head++

	if buf[head] != 0x00 {
		log1("reserved header not zero")
		dump(buf)
		_ = c.Close()
		return
	}

	logRead("\treserved header: " + blue + "0x00" + reset)

	head++

	if buf[head] != 0x01 {
		log1("bad address type, only ipv4 address supported")
		dump(buf)
		log0("responding with 0x08 (bad address type)")
		_, _ = c.Write([]byte{0x05, 0x08})
		_ = c.Close()
		return
	}

	target := net.IP{
		buf[head+1], buf[head+2], buf[head+3], buf[head+4],
	}

	head += 5

	logRead("\ttarget addr: " + blue + target.String() + reset)

	port := uint16(buf[head]) | uint16(buf[head+1])

	logRead("\ttarget port: " + blue + strconv.Itoa(int(port)) + reset)

	targetStr := target.String() + ":" + strconv.Itoa(int(port))

	ap, err := netip.ParseAddrPort(targetStr)
	if err != nil {
		log1(err.Error())
		log0("{0x05,0x01} (general failure)")
		_, _ = c.Write([]byte{0x05, 0x01})
		_ = c.Close()
		return
	}
	targetHost := ap.String()

	log("connecting to "+targetHost+"... ", "")

	var conn net.Conn
	if conn, e = net.DialTimeout("tcp", targetHost, time.Duration(5)*time.Second); e != nil {
		log1("\t" + e.Error())
		logWrite(red + "0x01 (general failure)" + reset)
		_, _ = c.Write([]byte{0x05, 0x01})
		_ = c.Close()
		return
	}

	_, _ = os.Stderr.Write([]byte(green + "success" + reset + "\n"))
	localAddr := c.LocalAddr().(*net.TCPAddr).IP.To4()
	localPortUint16 := uint16(c.LocalAddr().(*net.TCPAddr).Port)
	localPortBytes := []byte{byte(localPortUint16 >> 8), byte(localPortUint16)}

	logWrite(green + "{0x05, 0x00, 0x00, 0x01} (success)" + reset)
	written, e = c.Write([]byte{0x05, 0x00, 0x00, 0x01})
	if e != nil {
		log1(e.Error())
		return
	}
	if written != 4 {
		log1("short write")
		return
	}

	logWrite(blue + fmtHex(localAddr) + reset + gray + " ("+localAddr.String()+")" + reset)
	written, e = c.Write(localAddr)
	if e != nil {
		log1(e.Error())
		return
	}
	if written != 4 {
		log1("short write")
		dump(localAddr[:written])
		return
	}

	logWrite(blue + fmtHex(localPortBytes) + reset + gray + " ("+strconv.Itoa(int(localPortUint16))+")" + reset)
	written, e = c.Write(localPortBytes)
	if e != nil {
		log1(e.Error())
		return
	}
	if written != 2 {
		log1("short write")
		dump(localPortBytes[:written])
		return
	}

	log("forwarding data...")

	defer func() { _ = conn.Close() }()
	if e = pipe(c, conn); e != nil {
		switch {
		case errors.Is(e, io.EOF):
			finished = true
			log0("EOF")
			return
		case e == nil:
			finished = true
			return
		default:
			log1(e.Error())
			return
		}
	}
	finished = true
}

func pipe(socksClient net.Conn, target net.Conn) error {
	defer func() { _ = target.Close() }()
	// caller closes socksClient
	// defer func() { _ = socksClient.Close() }()

	outBuf := make([]byte, 1024)
	inBuf := make([]byte, 1024)
	eChan := make(chan error, 2)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer cancel()
		for {
			_ = target.SetDeadline(time.Now().Add(time.Duration(5) * time.Second))
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, e := target.Read(inBuf)
			if e != nil {
				eChan <- e
				return
			}
			if n == 0 {
				eChan <- io.EOF
				return
			}
			_, e = socksClient.Write(inBuf[:n])
			if e != nil {
				eChan <- e
				return
			}
		}
	}()

	go func() {
		defer cancel()
		for {
			_ = socksClient.SetDeadline(time.Now().Add(time.Duration(5) * time.Second))
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, e := socksClient.Read(outBuf)
			if e != nil {
				eChan <- e
				return
			}
			if n == 0 {
				eChan <- io.EOF
				return
			}
			_, e = target.Write(outBuf[:n])
			if e != nil {
				eChan <- e
			}
		}
	}()

	select {
	case e := <-eChan:
		return e
	case <-ctx.Done():
		return nil
	}
}

func serve() {
	if len(os.Args) < 2 {
		return
	}

	var l net.Listener
	var e error
	go func() {
		l, e = net.Listen("tcp", os.Args[1])
		if e != nil {
			println(e.Error())
			os.Exit(1)
		}
	}()

	time.Sleep(time.Duration(5) * time.Millisecond)
	println("listening on " + os.Args[1])

	for {
		c, e := l.Accept()
		if e != nil {
			println(e.Error())
			continue
		}
		go handle(c)
	}
}
