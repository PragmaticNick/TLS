package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"io"
)

var ProtocolVersion = [2]byte{0x03, 0x03}

type TlsRecord struct {
	ContentType     byte
	ProtocolVersion [2]byte
	Length          uint16
	Payload         []byte
}

func (r *TlsRecord) Serialize() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, r.ContentType)
	binary.Write(buffer, binary.BigEndian, r.ProtocolVersion)
	binary.Write(buffer, binary.BigEndian, r.Length)
	buffer.Write(r.Payload)

	return buffer.Bytes()
}

func (r *TlsRecord) Parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &r.ContentType)
	binary.Read(reader, binary.BigEndian, &r.ProtocolVersion)
	binary.Read(reader, binary.BigEndian, &r.Length)
	r.Payload = make([]byte, r.Length)
	reader.Read(r.Payload)
}

type HandshakeMessage struct {
	MessageType byte
	Length      [3]byte
	Payload     []byte
}

func (h *HandshakeMessage) Serialize() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, h.MessageType)
	binary.Write(buffer, binary.BigEndian, h.Length)
	buffer.Write(h.Payload)

	return buffer.Bytes()
}

func (h *HandshakeMessage) Parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &h.MessageType)
	binary.Read(reader, binary.BigEndian, &h.Length)

	h.Payload = make([]byte, int(h.Length[0])<<16|int(h.Length[1])<<8|int(h.Length[2]))
	reader.Read(h.Payload)
}

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

type ServerHello struct {
	ProtocolVersion   [2]byte
	Random            Random
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	Extension         []Extension
}

func (s *ServerHello) Parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &s.ProtocolVersion)
	binary.Read(reader, binary.BigEndian, &s.Random.UnixTime)
	binary.Read(reader, binary.BigEndian, &s.Random.RandomBytes)

	var sessionIDLength byte = 0
	binary.Read(reader, binary.BigEndian, &sessionIDLength)
	s.SessionID = make([]byte, sessionIDLength)
	reader.Read(s.SessionID[:sessionIDLength])

	binary.Read(reader, binary.BigEndian, &s.CipherSuite)
	binary.Read(reader, binary.BigEndian, &s.CompressionMethod)

	// TODO: Extensions
}

func ParseCertificates(reader io.Reader) []*x509.Certificate {
	certificates := []*x509.Certificate{}

	lengthBytes := make([]byte, 3)
	reader.Read(lengthBytes)
	totalLength := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

	read := 0
	for read < totalLength {
		reader.Read(lengthBytes)
		length := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

		certBytes := make([]byte, length)
		reader.Read(certBytes)

		certificate, err := x509.ParseCertificate(certBytes)
		if err != nil {
			panic(err.Error())
		}

		certificates = append(certificates, certificate)
		read += length + 3
	}

	return certificates
}
