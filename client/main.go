package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		panic(err.Error())
	}

	// Client Hello
	var randBytes [28]byte
	rand.Read(randBytes[:])

	random := Random{
		UnixTime:    uint32(time.Now().Unix()),
		RandomBytes: randBytes,
	}

	clientHello := ClientHello{
		ProtocolVersion: ProtocolVersion,
		Random:          random,
		SessionID:       []byte{},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions:         nil,
	}

	clientHelloBytes := clientHello.Serialize()
	handshakeMessage := HandshakeMessage{
		MessageType: 0x01,
		Length:      [3]byte{0, 0, byte(len(clientHelloBytes))},
		Payload:     clientHelloBytes,
	}

	handshakeMessageBytes := handshakeMessage.Serialize()
	tlsRecord := TlsRecord{
		ContentType:     0x16,
		ProtocolVersion: ProtocolVersion,
		Length:          uint16(len(handshakeMessageBytes)),
		Payload:         handshakeMessageBytes,
	}

	conn.Write(tlsRecord.Serialize())

	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)

	reader := bytes.NewReader(buffer[:n])

	tlsRecord.Parse(reader)
	fmt.Printf("tlsRecord.ContentType: %v\n", tlsRecord.ContentType)
	fmt.Printf("tlsRecord.ProtocolVersion: %v\n", tlsRecord.ProtocolVersion)
	fmt.Printf("tlsRecord.Length: %v\n", tlsRecord.Length)
	fmt.Println()

	handshakeMessage.Parse(bytes.NewReader(tlsRecord.Payload))
	fmt.Printf("handshakeMessage.MessageType: %v\n", handshakeMessage.MessageType)
	fmt.Printf("handshakeMessage.Length: %v\n", handshakeMessage.Length)
	fmt.Printf("handshakeMessage.Payload: %v\n", handshakeMessage.Payload)
	fmt.Println()

	serverHello := ServerHello{}
	serverHello.Parse(bytes.NewReader(handshakeMessage.Payload))
	fmt.Printf("serverHello.ProtocolVersion: %v\n", serverHello.ProtocolVersion)
	fmt.Printf("serverHello.Random: %v\n", serverHello.Random)
	fmt.Printf("serverHello.SessionID: %v\n", serverHello.SessionID)
	fmt.Printf("serverHello.CipherSuite: %v\n", serverHello.CipherSuite)
	fmt.Printf("serverHello.CompressionMethod: %v\n", serverHello.CompressionMethod)
	fmt.Println()

	fmt.Printf("n: %v\n", n)

	tlsRecord.Parse(reader)
	fmt.Printf("tlsRecord.ContentType: %v\n", tlsRecord.ContentType)
	fmt.Printf("tlsRecord.ProtocolVersion: %v\n", tlsRecord.ProtocolVersion)
	fmt.Printf("tlsRecord.Length: %v\n", tlsRecord.Length)
	fmt.Println()

	handshakeMessage.Parse(bytes.NewReader(tlsRecord.Payload))
	fmt.Printf("handshakeMessage.MessageType: %v\n", handshakeMessage.MessageType)
	fmt.Printf("handshakeMessage.Length: %v\n", handshakeMessage.Length)
	fmt.Println()

	certs := ParseCertificates(bytes.NewReader(handshakeMessage.Payload))
	for _, cert := range certs {
		fmt.Printf("cert.Issuer.Country: %v\n", cert.Issuer.Country)
	}

	tlsRecord.Parse(reader)
	handshakeMessage.Parse(bytes.NewReader(tlsRecord.Payload))
	fmt.Printf("handshakeMessage.MessageType: %v\n", handshakeMessage.MessageType)
	fmt.Printf("handshakeMessage.Length: %v\n", handshakeMessage.Length)
}
