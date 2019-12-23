#include "PacketReader.h"
#include <ostream>
#include <iostream>

std::vector<AdapterData> GetAdapterList()
{
    std::vector<AdapterData> adapterList;
    pcap_if_t* alldevs = nullptr;
    pcap_if_t* d = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list from the local machine, auth is not needed
    if ( pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1 )
    {
        for ( d = alldevs; d != NULL; d = d->next ) // Populate the list
            adapterList.push_back(d);

        pcap_freealldevs(alldevs);
    }
    return adapterList;
}

bool OpenAdapter(const std::string &name, pcap_t* &adapter)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    adapter = pcap_open(name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    return adapter != nullptr;
}

void FreeAdapter(pcap_t* adapter)
{
    pcap_close(adapter);
}

SocketAddress::SocketAddress(sockaddr* rhs)
{
    if ( rhs != nullptr )
    {
        this->SockAddr.sa_family = rhs->sa_family;
        if ( rhs->sa_family == AF_INET )
        {
            this->SockAddrIn.sin_port = ((sockaddr_in*)rhs)->sin_port;
            this->SockAddrIn.sin_addr = ((sockaddr_in*)rhs)->sin_addr;
            memcpy(this->SockAddrIn.sin_zero, ((sockaddr_in*)rhs)->sin_zero, sizeof(this->SockAddrIn.sin_zero));
        }
        else if ( rhs->sa_family == AF_INET6 )
        {
            this->SockAddrIn6.sin6_port = ((sockaddr_in6*)rhs)->sin6_port;
            this->SockAddrIn6.sin6_flowinfo = ((sockaddr_in6*)rhs)->sin6_flowinfo;
            this->SockAddrIn6.sin6_addr = ((sockaddr_in6*)rhs)->sin6_addr;
            this->SockAddrIn6.sin6_scope_id = ((sockaddr_in6*)rhs)->sin6_scope_id;
        }
    }
    else
        this->SockAddr.sa_family = 0;
}

bool SocketAddress::isValid()
{
    return SockAddr.sa_family != 0;
}

bool SocketAddress::isIpv4Address()
{
    return this->SockAddr.sa_family == AF_INET;
}

bool SocketAddress::isIpv6Address()
{
    return this->SockAddr.sa_family == AF_INET6;
}

bool isPublicIPv4(u8* a)
{
    return !(
        (a[0] == 0) || // Is a source address from the current network
        (a[0] == 10) || // Private 10.x.x.x address
        (a[0] == 100 && a[1] >= 64 && a[1] < 128) || // Shared Address Space
        (a[0] == 127) || // Loopback
        (a[0] == 169 && a[1] == 254) || // Link-local
        (a[0] == 172 && a[1] >= 16 && a[1] < 32) || // Private 172.16.x.x address
        (a[0] == 192 && a[1] == 0 && a[2] == 0) || // IETF Protocol Assignments
        (a[0] == 192 && a[1] == 0 && a[2] == 2) || // TEST-NET-1, documentation and examples
        (a[0] == 192 && a[1] == 88 && a[2] == 99) || // IPv6 to IPv4 relay
        (a[0] == 192 && a[1] == 168) || // Private 192.168.x.x address
        (a[0] == 198 && a[1] >= 18 && a[1] < 20) || // Network benchmark tests
        (a[0] == 198 && a[1] == 51 && a[2] == 100) || // TEST-NET-2, documentation and examples
        (a[0] == 203 && a[1] == 0 && a[2] == 113) || // TEST-NET-3, documentation and examples
        (a[0] >= 224 && a[0] < 240) || // IP multicast (former Class D network)
        (a[0] >= 240) // Reserved (former Class E network) OR Broadcast address (255.255.255.255)
        );
}

bool SocketAddress::isPublicAddress()
{
    if ( this->SockAddr.sa_family == AF_INET ) // IPv4
    {
        return isPublicIPv4((u8*)&SockAddrIn.sin_addr.s_addr);
    }
    else if ( this->SockAddr.sa_family == AF_INET6 ) // IPv6
    {
        u8* addrBytes = &this->SockAddrIn6.sin6_addr.u.Byte[0];
        u8 firstByte = addrBytes[0];
        u8 secondByte = addrBytes[1];
        u8 lastByte = addrBytes[15];
        if ( firstByte == 0xFE && secondByte >= 0x80 && secondByte < 0xC0 ) // Link-Local unicast
            return false;
        else if ( firstByte == 0xFF && secondByte == 0x00 ) // Multicast
            return false;
        else if ( lastByte == 0 || lastByte == 1 )
        {
            for ( u8 i = 0; i < 8; i++ ) // Check if the first 8 bytes are 0
            {
                if ( addrBytes[i] != 0 )
                    return true; // Has non-zero value in the first 8 bytes, making this a Global Unicast (public) address
            }

            // Check for any private, embedded IPv4 addresses
            if ( addrBytes[8] == 0x0 && addrBytes[9] == 0x0 && addrBytes[10] == 0x0 && addrBytes[11] == 0x0 &&
                addrBytes[12] == 0x0 && addrBytes[13] == 0x0 && addrBytes[14] == 0x0 &&
                (addrBytes[15] == 0x0 || addrBytes[15] == 0x1) )
            {
                return false; // Unspecified (00...0) or Loopback (00...1)
            }
            else if ( (addrBytes[8] == 0xF && addrBytes[9] == 0xF && addrBytes[10] == 0xF && addrBytes[11] == 0xF) )
            {
                return isPublicIPv4(&addrBytes[12]);
            }
            else
                return true; // Is not Unspecified, Loopback, or mapped to an IPv4 address, so it's a Global Unicast (public) address
        }
        else
            return true; // First and last bytes don't suggest a special or private address, so it's a Global Unicast (public) address
    }
    else
        return false; // Unidentified type, return false
}

std::ostream& operator<<(std::ostream &os, const SocketAddress &socketAddress)
{
    if ( socketAddress.SockAddr.sa_family == AF_INET ) // IPv4
    {
        u8* p = (u8*)&socketAddress.SockAddrIn.sin_addr.s_addr;
        return (os << std::to_string(p[0]) << "." << std::to_string(p[1]) << "." << std::to_string(p[2]) << "." << std::to_string(p[3]));
    }
    else if ( socketAddress.SockAddr.sa_family == AF_INET6 ) // IPv6
    {
        socklen_t sockaddrlen = 0;
        sockaddr* address = nullptr;
#ifdef WIN32
        address = (sockaddr*)(new sockaddr_in6);
        sockaddr_in6* sock6 = (sockaddr_in6*)address;
        sockaddrlen = sizeof(struct sockaddr_in6);
#else
        address = (sockaddr*)(new sockaddr_storage);
        sockaddr_storage* sock6 = (sockaddr_storage*)address;
        sockaddrlen = sizeof(struct sockaddr_storage);
#endif
        sock6->sin6_family = socketAddress.SockAddrIn6.sin6_family;
        sock6->sin6_port = socketAddress.SockAddrIn6.sin6_port;
        sock6->sin6_flowinfo = socketAddress.SockAddrIn6.sin6_flowinfo;
        sock6->sin6_addr = socketAddress.SockAddrIn6.sin6_addr;
        sock6->sin6_scope_id = socketAddress.SockAddrIn6.sin6_flowinfo;

        char ip6str[128] = {};
        if ( getnameinfo(address, sockaddrlen, ip6str, sizeof(ip6str), NULL, 0, NI_NUMERICHOST) == 0 )
            return (os << ip6str);
    }
    return os;
}

AdapterAddress::AdapterAddress(pcap_addr* rhs) :
    addr(rhs != nullptr ? rhs->addr : nullptr),
    netmask(rhs != nullptr ? rhs->netmask : nullptr),
    broadaddr(rhs != nullptr ? rhs->broadaddr : nullptr),
    dstaddr(rhs != nullptr ? rhs->dstaddr : nullptr)
{

}

AdapterData::AdapterData() : name(""), description(""), flags(0)
{

}

AdapterData::AdapterData(pcap_if_t* rhs) :
    name(rhs != nullptr ? rhs->name : ""),
    description(rhs != nullptr ? rhs->description : ""),
    flags(rhs != nullptr ? rhs->flags : 0)
{
    for ( pcap_addr* a = rhs->addresses; a != NULL; a = a->next )
        addresses.push_back(a);
}

u32 AdapterData::GetNetMask()
{
    if ( addresses.size() > 0 )
        return addresses.at(0).netmask.SockAddrIn.sin_addr.S_un.S_addr;
    else
        return 0x00FFFFFF; // Class C by default
}
