#include "PacketReader.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <time.h>

bool SelectAdapter(bool selectOnlyPublic, std::istream &is, std::ostream &os, AdapterData &selectedAdapter);
void ReadPackets(pcap_t* adapterHandle);
void ReadUdpIPv4Packet(timeval &timeStamp, IPv4PacketHeader &ipHeader, UdpPacketHeader &udpHeader, const u8* udpData, u16 udpDataSize);
void ReadTcpIPv4Packet(timeval &timeStamp, IPv4PacketHeader &ipHeader, TcpPacketHeader &udpHeader, const u8* tcpData, u16 tcpDataSize);
const char* timeToString(timeval &timeValue);

int main()
{
    AdapterData selectedAdapter;
    char filter[] = "udp portrange 4444-4445 or tcp portrange 4444-4445";
    bpf_program fcode = {};
    pcap_t* adapterHandle = nullptr;

    if ( SelectAdapter(true, std::cin, std::cout, selectedAdapter) )
    {
        if ( OpenAdapter(selectedAdapter.name, adapterHandle) )
        {
            if ( pcap_datalink(adapterHandle) == DLT_EN10MB )
            {
                if ( pcap_compile(adapterHandle, &fcode, filter, 1, selectedAdapter.GetNetMask()) != -1 &&
                    pcap_setfilter(adapterHandle, &fcode) != -1 )
                {
                    std::cout << "Reading packets matching: \"" << filter << "\"" << std::endl;
                    ReadPackets(adapterHandle);
                }
                else
                    std::cout << "Failed to set filter: \"" << filter << "\"" << std::endl;
            }
            else
                std::cout << "Unsupported data-link type: " << pcap_datalink(adapterHandle) << std::endl;

            FreeAdapter(adapterHandle);
        }
    }

    std::cin.sync();
    std::cin.get();
    return 0;
}

bool SelectAdapter(bool selectOnlyPublic, std::istream &is, std::ostream &os, AdapterData &selectedAdapter)
{
    std::vector<AdapterData> adapterList = GetAdapterList();

    if ( adapterList.size() == 0 )
        return false;
    else if ( adapterList.size() == 1 )
    {
        selectedAdapter = adapterList[0];
        return true;
    }

    if ( selectOnlyPublic )
    {
        int numAdaptersWithPublicAddresses = 0;
        AdapterData* adapterWithPublicAddress = nullptr;

        for ( AdapterData &adapter : adapterList )
        {
            for ( AdapterAddress &address : adapter.addresses )
            {
                if ( address.addr.isPublicAddress() )
                {
                    adapterWithPublicAddress = &adapter;
                    numAdaptersWithPublicAddresses++;
                    break;
                }
            }
        }

        if ( selectOnlyPublic && numAdaptersWithPublicAddresses == 1 )
        {
            selectedAdapter = *adapterWithPublicAddress;
            return true;
        }
    }

    u32 adapterNum = 0;
    for ( AdapterData &adapter : adapterList )
    {
        std::string padding = (adapterNum < 10 ? "    " : "     ");
        os << adapterNum << " - " << (adapter.description.size() > 0 ? adapter.description :
            (adapter.name.size() > 0 ? adapter.name : "(No Description)")) << std::endl;

        for ( AdapterAddress &address : adapter.addresses )
        {
            bool isPublic = address.addr.isPublicAddress();
            bool isv4 = address.addr.isIpv6Address();
            os << padding << (isPublic ? "Public " : "Private ")
                << (isv4 ? "IPv4 - " : "IPv6 - ") << address.addr;
            if ( address.netmask.isValid() )
                os << padding << "Mask - " << address.netmask;
            os << std::endl;
        }
        os << std::endl;
        adapterNum++;
    }

    adapterNum = 0xFFFFFFFF;
    do
    {
        os << "Please select an adapter: ";
        std::string inputText;
        std::getline(is, inputText);
        std::stringstream ss(inputText);
        ss >> adapterNum;
    } while ( adapterNum >= adapterList.size() );

    selectedAdapter = adapterList[adapterNum];
    return true;
}

void ReadPackets(pcap_t* adapterHandle)
{
    int result = 0;
    const u8* pkt_data = nullptr;
    pcap_pkthdr* header = nullptr;

    while ( (result = pcap_next_ex(adapterHandle, &header, &pkt_data)) >= 0 )
    {
        if ( result == 0 ) // Timeout elapsed
            continue;

        if ( header->len > EthernetHeaderSize )
        {
            if ( ((pkt_data[EthernetHeaderSize] & 0xF0) >> 4) == 4 &&
                header->len >= EthernetHeaderSize + MinimumIpv4HeaderSize )
            {
                IPv4PacketHeader* ipHeader = (IPv4PacketHeader*)(&pkt_data[EthernetHeaderSize]);
                u16 ipHeaderLength = 4 * ((u16)(ipHeader->Version_IHL & 0x0F));
                u16 ipPacketLength = (u16)std::min((bpf_u_int32)ntohs(ipHeader->nTotalLength), header->len - EthernetHeaderSize);

                if ( ipHeader->Protocol == 0x11 && header->len >= EthernetHeaderSize + (u32)ipHeaderLength + UdpHeaderSize )
                {
                    UdpPacketHeader* udpHeader = (UdpPacketHeader*)(&pkt_data[EthernetHeaderSize + ipHeaderLength]);
                    u16 udpPacketLength = ntohs(udpHeader->nLength);
                    ReadUdpIPv4Packet(header->ts, *ipHeader, *udpHeader,
                        &pkt_data[EthernetHeaderSize + ipHeaderLength + 8], udpPacketLength - 8);
                }
                else if ( ipHeader->Protocol == 0x06 && header->len >= EthernetHeaderSize + ipHeaderLength + MinimumTcpHeaderSize )
                {
                    TcpPacketHeader* tcpHeader = (TcpPacketHeader*)(&pkt_data[EthernetHeaderSize + ipHeaderLength]);
                    u16 tcpHeaderLength = 4 * ((u16)((tcpHeader->DataOffset_Reserved_NS & 0xF0) >> 4));
                    u16 tcpPacketLength = ipPacketLength - tcpHeaderLength;
                    ReadTcpIPv4Packet(header->ts, *ipHeader, *tcpHeader,
                        &pkt_data[EthernetHeaderSize + ipHeaderLength + tcpHeaderLength], ipPacketLength - tcpHeaderLength);
                }
                //else // Unimplemented or invalid protocol/packetSize
            }
            else if ( ((pkt_data[14] & 0xF0) >> 4) == 6 )
            {
                std::cout << "Error: IPv6 Unimplemented." << std::endl;
            }
            //else // Unimplemented or invalid ipHeaderVersion/packetSize
        }
        //else // Unimplemented or invalid frameType/frameSize
    }
}

void ReadUdpIPv4Packet(timeval &timeStamp, IPv4PacketHeader &ipHeader, UdpPacketHeader &udpHeader, const u8* udpData, u16 udpDataSize)
{
    u16 sourcePort = ntohs(udpHeader.nSourcePort);
    u16 destPort = ntohs(udpHeader.nDestinationPort);
    std::cout << timeToString(timeStamp)
        << " - IPv4 UDP (" << sourcePort << ", " << destPort << "): "
        << udpDataSize << " bytes" << std::endl;

    for ( int i = 0; i < udpDataSize; i++ )
        std::cout << std::hex << (int)udpData[i];

    std::cout << std::nouppercase << std::dec << std::endl;

    for ( int i = 0; i < udpDataSize; i++ )
    {
        if ( udpData[i] >= 32 && udpData[i] < 127 )
            std::cout << udpData[i];
        else
            std::cout << ' ';
    }

    std::cout << std::endl << std::endl;
}

void ReadTcpIPv4Packet(timeval &timeStamp, IPv4PacketHeader &ipHeader, TcpPacketHeader &tcpHeader, const u8* tcpData, u16 tcpDataSize)
{
    u16 sourcePort = ntohs(tcpHeader.nSourcePort);
    u16 destPort = ntohs(tcpHeader.nDestinationPort);
    std::cout << timeToString(timeStamp)
        << " - IPv4 TCP (" << sourcePort << ", " << destPort << "): "
        << tcpDataSize << " bytes" << std::endl;

    for ( int i = 0; i < tcpDataSize; i++ )
        std::cout << std::hex << std::uppercase << (int)tcpData[i];

    std::cout << std::nouppercase << std::dec << std::endl;

    for ( int i = 0; i < tcpDataSize; i++ )
    {
        if ( tcpData[i] >= 32 && tcpData[i] < 127 )
            std::cout << tcpData[i];
        else
            std::cout << ' ';
    }

    std::cout << std::endl << std::endl;
}

const char* timeToString(timeval &timeValue)
{
    static char timestr[16] = {};
    tm ltime = {};
    time_t local_tv_sec = timeValue.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
    return timestr;
}
