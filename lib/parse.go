package lib

import (
	"bytes"
	"encoding/binary"
)

const (
	// backward compatibility with golang 1.6 which does not have io.SeekCurrent
	seekCurrent = 1
)
func parseRawData(data []byte) *ConntrackFlow {
	s := &ConntrackFlow{}
	var proto uint8
	// First there is the Nfgenmsg header
	// consume only the family field
	reader := bytes.NewReader(data)
	binary.Read(reader, NativeEndian(), &s.FamilyType)

	// skip rest of the Netfilter header
	reader.Seek(3, seekCurrent)
	// The message structure is the following:
	// <len, NLA_F_NESTED|CTA_TUPLE_ORIG> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the forward flow
	// <len, NLA_F_NESTED|CTA_TUPLE_REPLY> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the reverse flow
	for reader.Len() > 0 {
		if nested, t, l := parseNfAttrTL(reader); nested {
			switch t {
			case CTA_TUPLE_ORIG:
				if nested, t, _ = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
					proto = parseIpTuple(reader, &s.Forward)
				}
			case CTA_TUPLE_REPLY:
				if nested, t, _ = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
					parseIpTuple(reader, &s.Reverse)
				} else {
					// Header not recognized skip it
					reader.Seek(int64(l), seekCurrent)
				}
			case CTA_COUNTERS_ORIG:
				s.Forward.Bytes, s.Forward.Packets = parseByteAndPacketCounters(reader)
			case CTA_COUNTERS_REPLY:
				s.Reverse.Bytes, s.Reverse.Packets = parseByteAndPacketCounters(reader)
			case CTA_PROTOINFO:
				s.TCPState = parseProtoInfo(reader)
			}
		}
	}
	if proto == TCP_PROTO {
		reader.Seek(64, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	} else if proto == UDP_PROTO {
		reader.Seek(16, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	}
	return s
}
func parseProtoInfo(reader *bytes.Reader) (state string){
	_, t, _, v := parseNfAttrTLV(reader)
	switch t {
	case CTA_PROTOINFO_TCP:
		switch v[2] {
		case CTA_PROTOINFO_TCP_STATE:
			state = tcpState[v[4]]
		}
	}
	return
}
func parseNfAttrTLV(r *bytes.Reader) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(r)

	value = make([]byte, len)
	binary.Read(r, binary.BigEndian, &value)
	return isNested, attrType, len, value
}
func parseNfAttrTL(r *bytes.Reader) (isNested bool, attrType, len uint16) {
	binary.Read(r, NativeEndian(), &len)
	len -= SizeofNfattr

	binary.Read(r, NativeEndian(), &attrType)
	isNested = (attrType & NLA_F_NESTED) == NLA_F_NESTED
	attrType = attrType & (NLA_F_NESTED - 1)

	return isNested, attrType, len
}
// This method parse the ip tuple structure
// The message structure is the following:
// <len, [CTA_IP_V4_SRC|CTA_IP_V6_SRC], 16 bytes for the IP>
// <len, [CTA_IP_V4_DST|CTA_IP_V6_DST], 16 bytes for the IP>
// <len, NLA_F_NESTED|nl.CTA_TUPLE_PROTO, 1 byte for the protocol, 3 bytes of padding>
// <len, CTA_PROTO_SRC_PORT, 2 bytes for the source port, 2 bytes of padding>
// <len, CTA_PROTO_DST_PORT, 2 bytes for the source port, 2 bytes of padding>
func parseIpTuple(reader *bytes.Reader, tpl *IpTuple) uint8 {
	for i := 0; i < 2; i++ {
		_, t, _, v := parseNfAttrTLV(reader)
		switch t {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			tpl.SrcIP = v
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			tpl.DstIP = v
		}
	}
	// Skip the next 4 bytes  nl.NLA_F_NESTED|nl.CTA_TUPLE_PROTO
	reader.Seek(4, seekCurrent)
	_, t, _, v := parseNfAttrTLV(reader)
	if t == CTA_PROTO_NUM {
		tpl.Protocol = uint8(v[0])
	}
	// Skip some padding 3 bytes
	reader.Seek(3, seekCurrent)
	for i := 0; i < 2; i++ {
		_, t, _ := parseNfAttrTL(reader)
		switch t {
		case CTA_PROTO_SRC_PORT:
			parseBERaw16(reader, &tpl.SrcPort)
		case CTA_PROTO_DST_PORT:
			parseBERaw16(reader, &tpl.DstPort)
		}
		// Skip some padding 2 byte
		reader.Seek(2, seekCurrent)
	}
	return tpl.Protocol
}
func parseBERaw16(r *bytes.Reader, v *uint16) {
	binary.Read(r, binary.BigEndian, v)
}

func parseBERaw64(r *bytes.Reader, v *uint64) {
	binary.Read(r, binary.BigEndian, v)
}
func parseByteAndPacketCounters(r *bytes.Reader) (bytes, packets uint64) {
	for i := 0; i < 2; i++ {
		switch _, t, _ := parseNfAttrTL(r); t {
		case CTA_COUNTERS_BYTES:
			parseBERaw64(r, &bytes)
		case CTA_COUNTERS_PACKETS:
			parseBERaw64(r, &packets)
		default:
			return
		}
	}
	return
}
