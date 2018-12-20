package lib

import (
	"net"
	"fmt"
	"golang.org/x/sys/unix"
)

type ConntrackTableType uint8
const (
	ConntrackTable = ConntrackTableType(1)
	ConntrackExpectTable = ConntrackTableType(2)
)

// InetFamily Family type
type InetFamily uint8

const (
	AF_INET = InetFamily(unix.AF_INET)
	AF_INET6 = InetFamily(unix.AF_INET6)
)
// The full conntrack flow structure is very complicated and can be found in the file:
// http://git.netfilter.org/libnetfilter_conntrack/tree/include/internal/object.h
// For the time being, the structure below allows to parse and extract the base information of a flow
type ipTuple struct {
	Bytes    uint64
	DstIP    net.IP
	DstPort  uint16
	Packets  uint64
	Protocol uint8
	SrcIP    net.IP
	SrcPort  uint16
}

type ConntrackFlow struct {
	FamilyType uint8
	Forward    ipTuple
	Reverse    ipTuple
	Mark       uint32
}

func (s *ConntrackFlow) String() string {
	// conntrack cmd output:
	// udp      17 src=127.0.0.1 dst=127.0.0.1 sport=4001 dport=1234 packets=5 bytes=532 [UNREPLIED] src=127.0.0.1 dst=127.0.0.1 sport=1234 dport=4001 packets=10 bytes=1078 mark=0
	return fmt.Sprintf("%s\t%d src=%s dst=%s sport=%d dport=%d packets=%d bytes=%d\tsrc=%s dst=%s sport=%d dport=%d packets=%d bytes=%d mark=%d",
		L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
		s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.SrcPort, s.Forward.DstPort, s.Forward.Packets, s.Forward.Bytes,
		s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.SrcPort, s.Reverse.DstPort, s.Reverse.Packets, s.Reverse.Bytes,
		s.Mark)
}

type Handle struct {
	sockets      map[int]*SocketHandle
	lookupByDump bool
}
func (h *Handle) newNetlinkRequest(proto, flags int) *NetlinkRequest {
	// Do this so that package API still use nl package variable nextSeqNr
	if h.sockets == nil {
		return NewNetlinkRequest(proto, flags)
	}
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
		},
		Sockets: h.sockets,
	}
}
func (h *Handle) ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	res, err := h.dumpConntrackTable(table, family)
	if err != nil {
		return nil, err
	}

	// Deserialize all the flows
	var result []*ConntrackFlow
	for _, dataRaw := range res {
		result = append(result, parseRawData(dataRaw))
	}

	return result, nil
}
func (h *Handle) ConntrackTableFlush(table ConntrackTableType) error {
	req := h.newConntrackRequest(table, unix.AF_INET, IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}
func (h *Handle) newConntrackRequest(table ConntrackTableType, family InetFamily, operation, flags int) *NetlinkRequest {
	// Create the Netlink request object
	req := h.newNetlinkRequest((int(table)<<8)|operation, flags)
	// Add the netfilter header
	msg := &Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     NFNETLINK_V0,
		ResId:       0,
	}
	req.AddData(msg)
	return req
}

func (h *Handle) dumpConntrackTable(table ConntrackTableType, family InetFamily) ([][]byte, error) {
	req := h.newConntrackRequest(table, family, IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP)
	return req.Execute(unix.NETLINK_NETFILTER, 0)
}

func NewHandle(nlFamilies ...int) (*Handle, error) {
	return newHandle(None(), None(), nlFamilies...)
}
func newHandle(newNs, curNs NsHandle, nlFamilies ...int) (*Handle, error) {
	h := &Handle{sockets: map[int]*SocketHandle{}}
	fams := SupportedNlFamilies
	if len(nlFamilies) != 0 {
		fams = nlFamilies
	}
	for _, f := range fams {
		s, err := GetNetlinkSocketAt(newNs, curNs, f)
		if err != nil {
			return nil, err
		}
		h.sockets[f] = &SocketHandle{Socket: s}
	}
	return h, nil
}