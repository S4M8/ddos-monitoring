package main

import (
    "encoding/binary"
    "fmt"
    "net"
)

type IPv4Header struct {
	Version  uint8
	IHL      uint8
	ToS      uint8
	Length   uint16
	ID       uint16
	Flags    uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    net.IP
	DstIP    net.IP
}

type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	Flags    uint16
	Window   uint16
	Checksum uint16
	Urgent   uint16
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func parseIPv4Header(data []byte) (*IPv4Header, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	header := &IPv4Header{}
	header.Version = (data[0] >> 4) & 0x0F
	header.IHL = data[0] & 0x0F
	header.ToS = data[1]
	header.Length = binary.BigEndian.Uint16(data[2:4])
	header.ID = binary.BigEndian.Uint16(data[4:6])
	header.Flags = binary.BigEndian.Uint16(data[6:8])
	header.TTL = data[8]
	header.Protocol = data[9]
	header.Checksum = binary.BigEndian.Uint16(data[10:12])
	header.SrcIP = net.IP(data[12:16])
	header.DstIP = net.IP(data[16:20])

	return header, nil
}

func parseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for TCP header")
	}

	header := &TCPHeader{}
	header.SrcPort = binary.BigEndian.Uint16(data[0:2])
	header.DstPort = binary.BigEndian.Uint16(data[2:4])
	header.SeqNum = binary.BigEndian.Uint32(data[4:8])
	header.AckNum = binary.BigEndian.Uint32(data[8:12])
	header.Flags = binary.BigEndian.Uint16(data[12:14])
	header.Window = binary.BigEndian.Uint16(data[14:16])
	header.Checksum = binary.BigEndian.Uint16(data[16:18])
	header.Urgent = binary.BigEndian.Uint16(data[18:20])

	return header, nil
}

func parseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for UDP header")
	}

	header := &UDPHeader{}
	header.SrcPort = binary.BigEndian.Uint16(data[0:2])
	header.DstPort = binary.BigEndian.Uint16(data[2:4])
	header.Length = binary.BigEndian.Uint16(data[4:6])
	header.Checksum = binary.BigEndian.Uint16(data[6:8])

	return header, nil
}