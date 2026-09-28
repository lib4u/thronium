// Owned loopback DNS-over-QUIC/TCP fixture; no system trust/network changes.
package main

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/binary"
    "encoding/json"
    "encoding/pem"
    "io"
    "math/big"
    "net"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/miekg/dns"
    "github.com/sagernet/quic-go"
)

func must(err error) { if err != nil { panic(err) } }
func certificate(directory string) tls.Certificate {
    must(os.MkdirAll(directory,0700))
    caKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(err)
    ca:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Thronium private DoQ test CA"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(24*time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
    caDER,err:=x509.CreateCertificate(rand.Reader,ca,ca,&caKey.PublicKey,caKey);must(err)
    must(os.WriteFile(filepath.Join(directory,"ca.pem"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:caDER}),0600))
    key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(err)
    leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Owned loopback DoQ"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(24*time.Hour),IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},DNSNames:[]string{"resolver.fixture.invalid"},KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
    der,err:=x509.CreateCertificate(rand.Reader,leaf,ca,&key.PublicKey,caKey);must(err)
    keyDER,err:=x509.MarshalPKCS8PrivateKey(key);must(err)
    pair,err:=tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER}));must(err)
    return pair
}

func main() {
    directory:=os.Args[1]; must(os.MkdirAll(directory,0700))
    events,err:=os.OpenFile(filepath.Join(directory,"events.jsonl"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(err);defer events.Close()
    var lock sync.Mutex
    record:=func(value any){lock.Lock();defer lock.Unlock();must(json.NewEncoder(events).Encode(value))}
    pair:=certificate(directory)
    untrustedPair:=certificate(filepath.Join(directory,"untrusted"))
    ctx,cancel:=context.WithCancel(context.Background());defer cancel()
    answer:=func(input []byte,transport string) []byte {
        var query dns.Msg;must(query.Unpack(input));if len(query.Question)!=1 {panic("invalid question count")}
        q:=query.Question[0];name:=strings.ToLower(q.Name);if !strings.HasSuffix(name,".fixture.invalid.") {panic("nonfixture DNS")}
        record(map[string]any{"event":"query","transport":transport,"name":name,"type":q.Qtype,"wireID":query.Id})
        var reply dns.Msg;reply.SetReply(&query)
        if name=="resolver.fixture.invalid." {
            if q.Qtype==dns.TypeA {reply.Answer=[]dns.RR{&dns.A{Hdr:dns.RR_Header{Name:q.Name,Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.IPv4(127,0,0,1)}}}
        } else {
            marker:=byte(11);if transport=="tcp" {marker=22}
            if q.Qtype==dns.TypeA {reply.Answer=[]dns.RR{&dns.A{Hdr:dns.RR_Header{Name:q.Name,Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.IPv4(192,0,2,marker)}}}
            if q.Qtype==dns.TypeAAAA {address:=make(net.IP,16);copy(address,[]byte{0x20,0x01,0x0d,0xb8});address[15]=marker;reply.Answer=[]dns.RR{&dns.AAAA{Hdr:dns.RR_Header{Name:q.Name,Rrtype:dns.TypeAAAA,Class:dns.ClassINET},AAAA:address}}}
        }
        output,err:=reply.Pack();must(err);return output
    }
    exchange:=func(stream io.ReadWriter,transport string) error {
        var size [2]byte;if _,err:=io.ReadFull(stream,size[:]);err!=nil{return err}
        length:=binary.BigEndian.Uint16(size[:]);if length>4096||length<12 {panic("DNS frame bound")}
        message:=make([]byte,length);if _,err:=io.ReadFull(stream,message);err!=nil{return err}
        output:=answer(message,transport);binary.BigEndian.PutUint16(size[:],uint16(len(output)))
        if _,err:=stream.Write(append(size[:],output...));err!=nil{return err};return nil
    }
    listeners:=[]*quic.Listener{}
    connections:=[]*quic.Conn{}
    var connectionsLock sync.Mutex
    ports:=map[string]any{"ca":filepath.Join(directory,"ca.pem"),"events":filepath.Join(directory,"events.jsonl")}
    for _,name:=range []string{"direct","bootstrap","untrusted"} {
        selectedPair:=pair;if name=="untrusted" {selectedPair=untrustedPair}
        listener,err:=quic.ListenAddr("127.0.0.1:0",&tls.Config{GetCertificate:func(*tls.ClientHelloInfo)(*tls.Certificate,error){record(map[string]any{"event":"certificate","transport":name});return &selectedPair,nil},NextProtos:[]string{"doq"},MinVersion:tls.VersionTLS13},&quic.Config{});must(err)
        listeners=append(listeners,listener);ports[name]=listener.Addr().(*net.UDPAddr).Port
        go func(name string,listener *quic.Listener){
            for {connection,err:=listener.Accept(ctx);if err!=nil{return}
                connectionsLock.Lock();connections=append(connections,connection);connectionsLock.Unlock()
                record(map[string]any{"event":"connection","transport":name,"alpn":connection.ConnectionState().TLS.NegotiatedProtocol,"serverName":connection.ConnectionState().TLS.ServerName})
                go func(){for {stream,err:=connection.AcceptStream(ctx);if err!=nil{return};go func(){defer stream.Close();_ = exchange(stream,name)}()}}()
            }
        }(name,listener)
    }
    tcp,err:=net.Listen("tcp","127.0.0.1:0");must(err);ports["tcp"]=tcp.Addr().(*net.TCPAddr).Port
    go func(){for {client,err:=tcp.Accept();if err!=nil{return};go func(){defer client.Close();for exchange(client,"tcp")==nil{}}()}}()
    must(json.NewEncoder(os.Stdout).Encode(ports))
    _,_=io.Copy(io.Discard,os.Stdin)
    cancel();tcp.Close();for _,listener:=range listeners{listener.Close()}
    connectionsLock.Lock();for _,connection:=range connections{connection.CloseWithError(0,"fixture shutdown")};connectionsLock.Unlock()
    record(map[string]any{"event":"stopped"})
}
