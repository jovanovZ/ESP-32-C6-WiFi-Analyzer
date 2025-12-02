#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"



typedef struct {
    const char *prefix;
    const char *vendor;
} oui_entry_t;

static const oui_entry_t OUI_TABLE[] = {
    {"98:DE:D0", "TP-Link"},
    {"F4:F5:D8", "Huawei"},
    {"A4:50:46", "Xiaomi"},
    {"DC:A6:32", "Samsung"},
    {"FC:FC:48", "Apple"},
    {"A8:9C:ED", "Apple"},
    {"3C:5A:B4", "Sony"},
    {"04:D6:AA", "Intel"},
    {"00:1A:11", "Cisco"},
    {"00:17:88", "Netgear"},
};

static const char *lookup_vendor(const uint8_t *mac)
{
    static char vendor[32];
    char prefix[9];
    sprintf(prefix, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);

    for (int i = 0; i < sizeof(OUI_TABLE)/sizeof(OUI_TABLE[0]); i++) {
        if (strcmp(prefix, OUI_TABLE[i].prefix) == 0) {
            return OUI_TABLE[i].vendor;
        }
    }

    snprintf(vendor, sizeof(vendor), "Unknown (%s)", prefix);
    return vendor;
}



static void extract_ssid(const uint8_t *data, int len)
{
    int index = 36; 

    while (index < len - 2) {
        uint8_t tag  = data[index];
        uint8_t size = data[index+1];

        if (tag == 0x00) {  
            printf("    SSID: ");
            if (size == 0) printf("<hidden>\n");
            else {
                for (int i = 0; i < size; i++)
                    printf("%c", data[index + 2 + i]);
                printf("\n");
            }
            return;
        }
        index += size + 2;
    }
}



static void decode_rsn(const uint8_t *data, int len)
{
    int index = 36;

    while (index < len - 4) {
        uint8_t tag  = data[index];
        uint8_t size = data[index+1];

        if (tag == 0x30) { 
            printf("    Encryption: WPA2/WPA3\n");

            uint8_t group_cipher = data[index+2+3];
            if (group_cipher == 0x04) printf("    Group Cipher: CCMP-128 (AES)\n");
            if (group_cipher == 0x02) printf("    Group Cipher: TKIP\n");

            uint8_t pairwise_cipher = data[index+8+3];
            if (pairwise_cipher == 0x04) printf("    Unicast Cipher: CCMP-128 (AES)\n");
            if (pairwise_cipher == 0x02) printf("    Unicast Cipher: TKIP\n");

            uint8_t akm = data[index+12+3];
            if (akm == 0x02) printf("    AKM: PSK (WPA2-PSK)\n");
            if (akm == 0x08) printf("    AKM: SAE (WPA3)\n");

            return;
        }

        index += size + 2;
    }
}



static void decode_beacon_basic(const uint8_t *data)
{
    uint16_t interval = data[24+8] | (data[24+9] << 8);
    uint16_t caps = data[24+10] | (data[24+11] << 8);

    printf("    Beacon Interval: %d ms\n", interval);
    printf("    Privacy Enabled: %s\n", (caps & 0x10) ? "Yes" : "No");
}



static const char *get_frame_type(uint8_t fc0)
{
    uint8_t type = (fc0 >> 2) & 3;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    if (type == 0) {
        switch(subtype) {
            case 8: return "Beacon";
            case 4: return "Probe Request";
            case 5: return "Probe Response";
            case 0: return "Association Request";
            case 1: return "Association Response";
            case 11: return "Authentication";
            case 12: return "Deauthentication";
            default: return "Management";
        }
    }
    if (type == 1) return "Control";
    if (type == 2) return "Data";

    return "Unknown";
}



void channel_hopper(void *p)
{
    int ch = 1;
    while (1) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        printf("[CH] %d\n", ch);
        ch = (ch % 13) + 1;
        vTaskDelay(pdMS_TO_TICKS(300));
    }
}



   
static void check_eapol_handshake(const uint8_t *data, int len)
{
    if (len < 40) return;

    if (!(data[24] == 0xAA && data[25] == 0xAA && data[26] == 0x03 &&
          data[27] == 0x00 && data[28] == 0x00 && data[29] == 0x00 &&
          data[30] == 0x88 && data[31] == 0x8E)) {
        return; 
    }

    printf("  >>> WPA2/WPA3 EAPOL detected\n");

    const uint8_t *eapol = &data[32];

    uint8_t type = eapol[1];   
    uint16_t key_info = (eapol[5] << 8) | eapol[6];

    printf("    Key Info: 0x%04X\n", key_info);

    int ack = (key_info >> 7) & 1;
    int mic = (key_info >> 8) & 1;
    int install = (key_info >> 6) & 1;

    
    if (ack && !mic) {
        printf("    ---> Message 1/4 (ANonce from AP)\n");
    } else if (!ack && mic && !install) {
        printf("    ---> Message 2/4 (SNonce from STA)\n");
    } else if (ack && mic && install) {
        printf("    ---> Message 3/4\n");
    } else if (!ack && mic && !install) {
        printf("    ---> Message 4/4\n");
    } else {
        printf("    ---> Unknown EAPOL message\n");
    }
}



static void wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *ppkt = buf;
    const wifi_pkt_rx_ctrl_t *rx = &ppkt->rx_ctrl;
    const uint8_t *data = ppkt->payload;
    uint32_t len = rx->sig_len;

    if (len < 24) return;

    uint8_t fc0 = data[0];
    const char *frame = get_frame_type(fc0);

    char src[18], dst[18], bssid[18];

    sprintf(src, "%02X:%02X:%02X:%02X:%02X:%02X",
        data[10],data[11],data[12],data[13],data[14],data[15]);

    sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X",
        data[4],data[5],data[6],data[7],data[8],data[9]);

    sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
        data[16],data[17],data[18],data[19],data[20],data[21]);

    printf("\n================ PACKET ================\n");
    printf("%s | CH=%d | RSSI=%d | LEN=%d\n", frame, rx->channel, rx->rssi, (int)len);

    printf("  SRC: %s (%s)\n", src, lookup_vendor(data+10));
    printf("  DST: %s (%s)\n", dst, lookup_vendor(data+4));
    printf("  BSSID: %s (%s)\n", bssid, lookup_vendor(data+16));

    if (strcmp(frame, "Beacon") == 0) {
        extract_ssid(data, len);
        decode_beacon_basic(data);
        decode_rsn(data, len);
    }

    if (strcmp(frame, "Probe Request") == 0) {
        printf("  → Device is searching for networks\n");
        extract_ssid(data, len);
    }

    printf("HEX:\n");
    int dump_len = len < 256 ? len : 256;
    for (int i = 0; i < dump_len; i++) {
        printf("%02X ", data[i]);
        if ((i % 16) == 15) printf("\n");
    }
    
        // Detect WPA2/WPA3 Handshake
    if (strcmp(frame, "Data") == 0) {
        check_eapol_handshake(data, len);
    }


    printf("\n=======================================\n");
}






void app_main(void)
{
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    
   /* esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
    printf("Sniffer locked to channel 6\n");*/

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);

    xTaskCreate(channel_hopper, "chanhop", 4096, NULL, 1, NULL);

    printf("=== WIFI ANALYZER STARTED ===\n");
    
}
