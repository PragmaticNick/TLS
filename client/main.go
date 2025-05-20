package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type Extension struct {
	Type uint16
	Data []byte
}

type Random struct {
	UnixTime    uint32
	RandomBytes [28]byte
}

type ClientHello struct {
	ProtocolVersion    [2]byte
	Random             Random
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []Extension
}

func (c *ClientHello) Serialize() []byte {
	body := c.serializeBody()
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, []byte{0x01})
	binary.Write(buffer, binary.BigEndian, [3]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))})
	binary.Write(buffer, binary.BigEndian, body)

	return buffer.Bytes()
}

func (c *ClientHello) serializeBody() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, c.ProtocolVersion)
	binary.Write(buffer, binary.BigEndian, c.Random.UnixTime)
	binary.Write(buffer, binary.BigEndian, c.Random.RandomBytes)
	binary.Write(buffer, binary.BigEndian, uint8(len(c.SessionID)))
	binary.Write(buffer, binary.BigEndian, c.SessionID)
	binary.Write(buffer, binary.BigEndian, uint16(len(c.CipherSuites)*2))
	binary.Write(buffer, binary.BigEndian, c.CipherSuites)
	binary.Write(buffer, binary.BigEndian, uint8(len(c.CompressionMethods)))
	binary.Write(buffer, binary.BigEndian, c.CompressionMethods)

	extBuffer := new(bytes.Buffer)
	for _, ext := range c.Extensions {
		binary.Write(extBuffer, binary.BigEndian, ext.Type)
		binary.Write(extBuffer, binary.BigEndian, uint16(len(ext.Data)))
		binary.Write(extBuffer, binary.BigEndian, ext.Data)
	}

	binary.Write(buffer, binary.BigEndian, uint16(len(extBuffer.Bytes())))
	binary.Write(buffer, binary.BigEndian, extBuffer.Bytes())

	return buffer.Bytes()
}

var ProtocolVersion = [2]byte{0x03, 0x03}

func tlsRecord(payload []byte) []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, uint8(0x16))
	binary.Write(buffer, binary.BigEndian, ProtocolVersion)
	binary.Write(buffer, binary.BigEndian, uint16(len(payload)))
	binary.Write(buffer, binary.BigEndian, payload)

	return buffer.Bytes()
}

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

	conn.Write(tlsRecord(clientHello.Serialize()))

	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	fmt.Printf("data: %v\n", buffer[:n])
}
