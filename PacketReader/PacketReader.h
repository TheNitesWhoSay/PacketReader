/**
    To compile and run this code some additional setup may be required, the instructions that follow
    are for windows devices/vs2015, and may not apply to your target machines/development enviornment
    - Download and install Npcap on devices that will run this program https://nmap.org/download.html
    - Add an npcap folder containing the Npcap SDK to your project https://nmap.org/npcap/
    - Add ..\npcap\Include to your project's additional include directories
    - Add ..\npcap\Lib to your project's additional library directories
    - Include libraries: wpcap.lib;Packet.lib;Ws2_32.lib;
    - Add pre-processor definitions: NOMINMAX;_XKEYCHECK_H;WPCAP;HAVE_REMOTE;_MBCS;
*/
#ifndef PACKETREADER_H
#define PACKETREADER_H
#include <pcap.h>
#include <cstdint>
#include <string>
#include <vector>
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
class AdapterData;

// Gets a list of adapters on the machine, returns an empty list on faliure
std::vector<AdapterData> GetAdapterList();

// Attempts to open an adapter, when finished you should call FreeAdapter
bool OpenAdapter(const std::string &name, pcap_t* &adapter);

// Closes and cleans up any WinPCap data assocated with this adapter
void FreeAdapter(pcap_t* adapter);

class SocketAddress // Static copy of a sockaddr struct
{
public:
    SocketAddress(sockaddr* rhs);
    bool isValid();
    bool isIpv4Address();
    bool isIpv6Address();
    bool isPublicAddress();
    friend std::ostream& operator<<(std::ostream &os, const SocketAddress &socketAddress);

    union
    {
        struct
        {
            u16 sa_family;
            u8 sa_data[14];
        } SockAddr;

        struct
        {
            u16 sin_family;
            u16 sin_port;
            in_addr sin_addr;
            u8 sin_zero[8];
        } SockAddrIn;

        struct
        {
            u16 sin6_family;
            u16 sin6_port;
            u32 sin6_flowinfo;
            in6_addr sin6_addr;
            u32 sin6_scope_id;
        } SockAddrIn6;
    };
};

class AdapterAddress // Static copy of a pcap_addr struct
{
public:
    AdapterAddress(pcap_addr* rhs);

    SocketAddress addr;
    SocketAddress netmask;
    SocketAddress broadaddr;
    SocketAddress dstaddr;
};

class AdapterData // Static copy of a pcap_if_t struct
{
public:
    AdapterData();
    AdapterData(pcap_if_t* rhs);
    u32 GetNetMask();

    std::string name;
    std::string description;
    u32 flags;
    std::vector<AdapterAddress> addresses; // In this struct the next member of pcap_addr is unused
};

constexpr u32 EthernetHeaderSize = 14;
struct EthernetPacketHeader
{
    u8 Preamble[7];
    u8 SFD;
    u8 MACDest[6];
    u8 MACSource[6];

};

constexpr u32 MinimumIpv4HeaderSize = 20;
struct IPv4PacketHeader
{
    u8 Version_IHL; // ((Version_IHL & 0xF0) >> 4) is version, (Version_IHL & 0x0F) is IHL
    u8 DSCP_ECN; // ((DSCP_ECN & 0xFC) >> 2) is DSCP, (DSCP_ECN & 0x03) is ECN
    u16 nTotalLength; // TotalLength = ntohs(TotalLength)
    u16 nIdentification; // Identification = ntohs(Identification)
    u16 nFlags_FragmentOffset; // Flags = ((ntohs(nFlags_FragmentOffset) & 0xE000) >> 13),
                              // FragmentOffset = (ntohs(nFlags_FragmentOffset) & 0x1FFF)
    u8 TimeToLive;
    u8 Protocol;
    u16 nHeaderChecksum; // HeaderChecksum = ntosh(nHeaderChecksum)
    u32 nSourceIPAddress; // SourceIPAddress = ntohl(nSourceIPAddress)
    u32 nDestinationIPAddress; // DestinationIPAddress = ntohl(nDestinationIPAddress)
    u32 Options_PaddingTillDword[15]; // Acutal size of array is IHL-5, endianness details unknown
};

constexpr u32 MinimumIpv6HeaderSize = 1;
struct IPv6PacketHeader
{
    u8 Version_IHL; // 0x0F is version, 0xF0 is IHL
};

constexpr u32 UdpHeaderSize = 8;
struct UdpPacketHeader
{
    u16 nSourcePort; // SourcePort = ntohs(nSourcePort)
    u16 nDestinationPort; // DestinationPort = ntohs(DestinationPort)
    u16 nLength; // Length = ntohs(nLength)
    u16 nChecksum; // Checksum = ntohs(nChecksum)
};

constexpr u32 MinimumTcpHeaderSize = 20;
struct TcpPacketHeader
{
    u16 nSourcePort; // SourcePort = ntohs(nSourcePort)
    u16 nDestinationPort; // DestinationPort = ntohs(nDestinationPort)
    u32 nSequenceNumber; // SequenceNumber = ntohl(nSequenceNumber)
    u32 nAcknowledgmentNumber; // AcknowledgmentNumber = ntohl(nAcknowledgmentNumber)
    u8 DataOffset_Reserved_NS; // ((DataOffset_Reserved_NS & 0xF0) >> 4) is DataOffset, (DataOffset_Reserved_NS & 0x01) is NS
    u8 CWR_ECE_URG_ACK_PSH_RST_SYN_FIN;
    u16 nWindowSize; // nWindowSize = ntohs(nWindowSize)
    u16 nChecksum; // Checksum = ntohs(nChecksum)
    u16 nUrgentPointer; // UrgentPointer = ntohs(nUrgentPointer)
    u32 Options_PaddingTillDword[10]; // Actual size of the array is DataOffset - 5, endianness details unknown
};

#endif