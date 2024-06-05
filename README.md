# `clienthellod`: TLS ClientHello/QUIC Initial Packet reflection service
![Go Build Status](https://github.com/gaukas/clienthellod/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/gaukas/clienthellod)](https://goreportcard.com/report/github.com/gaukas/clienthellod)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fgaukas%2Fclienthellod.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fgaukas%2Fclienthellod?ref=badge_shield&issueType=license)
[![Go Doc](https://pkg.go.dev/badge/github.com/refraction-networking/water.svg)](https://pkg.go.dev/github.com/refraction-networking/water)

`clienthellod`, read as "client-hello-D", is a TLS ClientHello/QUIC Initial Packet reflection service. It can be used to parses TLS ClientHello messages and QUIC Initial Packets into human-readable and highly programmable formats such as JSON. 

Is is a part of the TLS fingerprintability research project which spans [tlsfingerprint.io](https://tlsfingerprint.io) and [quic.tlsfingerprint.io](https://quic.tlsfingerprint.io). It parses the ClientHello messages sent by TLS clients and QUIC Client Initial Packets sent by QUIC clients and display the parsed information in a human-readable format with high programmability. 

See [tlsfingerprint.io](https://tlsfingerprint.io) and [quic.tlsfingerprint.io](https://quic.tlsfingerprint.io) for more details about the project.

## Quick Start

`clienthellod` comes as a Go library, which can be used to parse both TLS and QUIC protocols. 

### TLS/QUIC Fingerprinter

```go
    tlsFingerprinter := clienthellod.NewTLSFingerprinter()
```

```go
    quicFingerprinter := clienthellod.NewQUICFingerprinter()
```

### TLS ClientHello

#### From a `net.Conn`

```go
    tcpLis, err := net.Listen("tcp", ":443")
    defer tcpLis.Close()

    conn, err := tcpLis.Accept()
	if err != nil {
        panic(err)
	}
    defer conn.Close()

	ch, err := clienthellod.ReadClientHello(conn) // reads ClientHello from the connection
    if err != nil {
        panic(err)
    }

    err := ch.ParseClientHello() // parses ClientHello's fields
    if err != nil {
        panic(err)
    }

    jsonB, err = json.MarshalIndent(ch, "", "  ")
    if err != nil {
        panic(err)
    }

    fmt.Println(string(jsonB))
    fmt.Println("ClientHello ID: " + ch.HexID) // prints ClientHello's original fingerprint ID calculated using observed TLS extension order
    fmt.Println("ClientHello NormID: " + ch.NormHexID) // prints ClientHello's normalized fingerprint ID calculated using sorted TLS extension list
```

#### From raw `[]byte`

```go
    ch, err := clienthellod.UnmarshalClientHello(raw)
    if err != nil {
        panic(err)
    }
    
    // err := ch.ParseClientHello() // no need to call again, UnmarshalClientHello automatically calls ParseClientHello
```

### QUIC Initial Packets (Client-sourced)

#### Single packet

```go
    udpConn, err := net.ListenUDP("udp", ":443")
    defer udpConn.Close()

    buf := make([]byte, 65535)
    n, addr, err := udpConn.ReadFromUDP(buf)
    if err != nil {
        panic(err)
    }

    ci, err := clienthellod.UnmarshalQUICClientInitialPacket(buf[:n]) // decodes QUIC Client Initial Packet
    if err != nil {
        panic(err)    
    }

    jsonB, err = json.MarshalIndent(cip, "", "  ")
    if err != nil {
        panic(err)
    }

    fmt.Println(string(jsonB)) // including fingerprint IDs of: ClientInitialPacket, QUIC Header, QUIC ClientHello, QUIC Transport Parameters' combination
```

#### Multiple packets

Implementations including Chrome/Chromium sends oversized Client Hello which does not fit into one single QUIC packet, in which case multiple QUIC Initial Packets are sent.

```go
    gci := GatherClientInitials() // Each GatherClientInitials reassembles one QUIC Client Initial Packets stream. Use a QUIC Fingerprinter for multiple potential senders, which automatically demultiplexes the packets based on the source address.
    
    udpConn, err := net.ListenUDP("udp", ":443")
    defer udpConn.Close()

    for {
        buf := make([]byte, 65535)
        n, addr, err := udpConn.ReadFromUDP(buf)
        if err != nil {
            panic(err)
        }

        if addr != knownSenderAddr {
            continue
        }

        ci, err := clienthellod.UnmarshalQUICClientInitialPacket(buf[:n]) // decodes QUIC Client Initial Packet
        if err != nil {
            panic(err)    
        }

        err = gci.AddPacket(ci)
        if err != nil {
            panic(err)
        }
    }
```

### Use with Caddy

We also provide clienthellod as a Caddy Module in `modcaddy`, which you can use with Caddy to capture ClientHello messages and QUIC Client Initial Packets. See [modcaddy](https://github.com/gaukas/clienthellod/tree/master/modcaddy) for more details.

## License

This project is developed and distributed under Apache-2.0 license. 

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fgaukas%2Fclienthellod.svg?type=large&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fgaukas%2Fclienthellod?ref=badge_large&issueType=license)
