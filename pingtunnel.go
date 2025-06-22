package pingtunnel

import (
    "bytes"
    "encoding/binary"
    "github.com/esrrhs/gohome/common"
    "github.com/esrrhs/gohome/loggo"
    "github.com/golang/protobuf/proto"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
    "net"
    "sync"
    "time"
)

// MIN_DATA_SIZE ensures the ICMP payload is large enough that the full packet > 1500 bytes
const MIN_DATA_SIZE = 1500

func sendICMP(
    id int,
    sequence int,
    conn icmp.PacketConn,
    server *net.IPAddr,
    target string,
    connId string,
    msgType uint32,
    data []byte,
    sproto int,
    rproto int,
    key int,
    tcpmode int,
    tcpmode_buffer_size int,
    tcpmode_maxwin int,
    tcpmode_resend_time int,
    tcpmode_compress int,
    tcpmode_stat int,
    timeout int,
) {
    m := &MyMsg{
        Id:                  connId,
        Type:                int32(msgType),
        Target:              target,
        Data:                data,
        Rproto:              int32(rproto),
        Key:                 int32(key),
        Tcpmode:             int32(tcpmode),
        TcpmodeBuffersize:   int32(tcpmode_buffer_size),
        TcpmodeMaxwin:       int32(tcpmode_maxwin),
        TcpmodeResendTimems: int32(tcpmode_resend_time),
        TcpmodeCompress:     int32(tcpmode_compress),
        TcpmodeStat:         int32(tcpmode_stat),
        Timeout:             int32(timeout),
        Magic:               int32(MyMsg_MAGIC),
    }

    mb, err := proto.Marshal(m)
    if err != nil {
        loggo.Error("sendICMP Marshal MyMsg error %s %s", server.String(), err)
        return
    }

    // Pad payload to ensure full packet > 1500 bytes
    if len(mb) < MIN_DATA_SIZE {
        padLen := MIN_DATA_SIZE - len(mb)
        mb = append(mb, bytes.Repeat([]byte{0}, padLen)...) // zero-padding
    }

    body := &icmp.Echo{
        ID:   id,
        Seq:  sequence,
        Data: mb,
    }

    msg := &icmp.Message{
        Type: ipv4.ICMPType(sproto),
        Code: 0,
        Body: body,
    }

    pkt, err := msg.Marshal(nil)
    if err != nil {
        loggo.Error("sendICMP Marshal error %s %s", server.String(), err)
        return
    }

    conn.WriteTo(pkt, server)
}

func recvICMP(
    workResultLock *sync.WaitGroup,
    exit *bool,
    conn icmp.PacketConn,
    recv chan<- *Packet,
) {
    defer common.CrashLog()

    workResultLock.Add(1)
    defer workResultLock.Done()

    buf := make([]byte, 10240)
    for !*exit {
        conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        n, srcaddr, err := conn.ReadFrom(buf)
        if err != nil {
            if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
                loggo.Info("Error read icmp message %s", err)
            }
            continue
        }
        if n <= 0 {
            continue
        }

        // Extract ICMP echo ID/Seq (offsets per IPv4 + ICMP)
        echoId := int(binary.BigEndian.Uint16(buf[4:6]))
        echoSeq := int(binary.BigEndian.Uint16(buf[6:8]))

        // Strip ICMP header (8 bytes) and trim zero-padding
        raw := buf[8:n]
        trimmed := bytes.TrimRight(raw, "\x00")
        if len(trimmed) == 0 {
            loggo.Debug("recvICMP no data after stripping padding")
            continue
        }

        my := &MyMsg{}
        if err := proto.Unmarshal(trimmed, my); err != nil {
            loggo.Debug("Unmarshal MyMsg error: %s", err)
            continue
        }
        if my.Magic != int32(MyMsg_MAGIC) {
            loggo.Debug("processPacket data invalid %s", my.Id)
            continue
        }

        recv <- &Packet{
            my:      my,
            src:     srcaddr.(*net.IPAddr),
            echoId:  echoId,
            echoSeq: echoSeq,
        }
    }
}

type Packet struct {
    my      *MyMsg
    src     *net.IPAddr
    echoId  int
    echoSeq int
}

const (
    FRAME_MAX_SIZE = 888
    FRAME_MAX_ID   = 1000000
)
