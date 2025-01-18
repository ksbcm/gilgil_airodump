#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NETWORKS 100

// IEEE 802.11 헤더 구조체 정의
struct ieee80211_hdr {
    unsigned short frame_control;
    unsigned short duration_id;
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    unsigned short seq_ctrl;
};

typedef struct {
    char ssid[32];
    char bssid[18];
    int channel;
    int signal_strength;
} Network;

Network networks[MAX_NETWORKS];
int network_count = 0;

void update_network(const char *ssid, const char *bssid, int channel, int signal_strength) {
    for (int i = 0; i < network_count; i++) {
        if (strcmp(networks[i].bssid, bssid) == 0) {
            networks[i].signal_strength = signal_strength;
            return;
        }
    }

    if (network_count < MAX_NETWORKS) {
        strncpy(networks[network_count].ssid, ssid, sizeof(networks[network_count].ssid) - 1);
        strncpy(networks[network_count].bssid, bssid, sizeof(networks[network_count].bssid) - 1);
        networks[network_count].channel = channel;
        networks[network_count].signal_strength = signal_strength;
        network_count++;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < sizeof(struct ieee80211_hdr)) {
        printf("패킷 길이가 충분하지 않습니다.\n");
        return;
    }

    struct ieee80211_hdr {
        unsigned short frame_control;
        unsigned short duration_id;
        unsigned char addr1[6];
        unsigned char addr2[6];
        unsigned char addr3[6];
        unsigned short seq_ctrl;
    };

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)packet;

    // BSSID 추출
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
             hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
             hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);

    // SSID 추출
    const u_char *ie_data = packet + sizeof(struct ieee80211_hdr);
    if (header->caplen < sizeof(struct ieee80211_hdr) + 2) {
        printf("정보 요소 데이터가 부족합니다.\n");
        return;
    }

    int ssid_length = ie_data[1];
    if (ssid_length > 32) {
        ssid_length = 32; // 최대 길이 제한
    }

    char ssid[33] = {0};
    memcpy(ssid, ie_data + 2, ssid_length);
    ssid[ssid_length] = '\0';

    // 채널 및 신호 강도는 아직 더미 값으로 사용
    int channel = 1;
    int signal_strength = -42;

    update_network(ssid, bssid, channel, signal_strength);
}

void print_networks() {
    system("clear");
    printf("SSID             BSSID              Channel   Signal Strength\n");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < network_count; i++) {
        printf("%-16s %-18s %-8d %-3d dBm\n",
               networks[i].ssid,
               networks[i].bssid,
               networks[i].channel,
               networks[i].signal_strength);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
        return 1;
    }

    while (1) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
        print_networks();
        usleep(500000);
    }

    pcap_close(handle);
    return 0;
}

