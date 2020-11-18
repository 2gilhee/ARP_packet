#include <iostream>
#include <typeinfo>
#include <bitset>
#include <iomanip>
#include <string.h>
#include <unistd.h> // for sleep() function
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
// #include "arp.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

using namespace std;
// struct ether_header ether;
// struct ether_arp arp;

void get_targetmac(u_int8_t* mac) {
  char buffer[18];
  char* address[6];
  int i = 0;

  system("sudo arp -a 192.168.80.129 | cut -f 4 -d \" \" > mac.txt ");

  FILE *fp = fopen("mac.txt", "r");
	fgets(buffer, sizeof(buffer), fp);

  char* temp = strtok(buffer, ":");
  while (temp != NULL){
    // printf("%s\n", temp);
    address[i] = temp;
    temp = strtok(NULL,":");
    i++;
  }

  for (i = 0; i<6; i++){
    // printf("address: %s\n", address[i]);
    mac[i] = strtol(address[i], NULL, 16);
    // printf("ip: %x\n", ip[i]);
  }

  // printf("%02x %02x %02x %02x %02x %02x\n",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  fclose(fp);
}

int get_mymac(uint8_t* hwaddr, char* device) {
  struct ifreq ifr;
  int s;

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  strcpy(ifr.ifr_name, device);
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
  // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

  close(s);
}

void get_ip(char* addr, u_int8_t* ip) {
  char* address[4];
  // u_int8_t* ip;
  int i = 0;

  char* temp = strtok(addr, ".");
  while (temp != NULL){
    // printf("%s\n", temp);
    address[i] = temp;
    temp = strtok(NULL,".");
    i++;
  }

  for (i = 0; i<4; i++){
    ip[i] = atoi(address[i]);
    // printf("%02x\n",ip[i]);
  }
}

void printMAC(uint8_t* add, int length){
  for(int i=0;i<length;i++){
    printf("%02x ", add[i]);
  }
  cout << endl;
}

void make_ether(struct ether_header* ether, uint8_t* hwaddr, uint8_t* target_mac) {
  // SET
  // uint8_t  dhost[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};	/* destination eth addr	*/
  // uint8_t  shost[6] = {0x00, 0x05, 0x56, 0xf0, 0xde, 0x7e};	/* source ether addr	*/
  uint16_t type = 0x0806;

  // COPY to ether struct
  memcpy(ether->ether_dhost, target_mac, sizeof(target_mac));
  memcpy(ether->ether_shost, hwaddr, sizeof(hwaddr));
  ether->ether_type = htons(type);

  // Print
  // cout << "ether->ehter_dhost: ";
  // printMAC(ether->ether_dhost, 6);
  // cout << "ether->ehter_shost: ";
  // printMAC(ether->ether_shost, 6);
  // printf("ether->ether_type: %04x\n", ether->ether_type);
}

void make_arp(struct ether_arp* arp, u_int8_t* sip, u_int8_t* tip,uint8_t* hwaddr, uint8_t* target_mac) {
  // SET
  unsigned short int ar_hrd = 0x0001;
  unsigned short int ar_pro = 0x0800;
  unsigned char ar_hln = 0x06;
  unsigned char ar_pln = 0x04;
  unsigned short int ar_op = 0x0001;
  // uint8_t arp_sha[6] = {0x00, 0x0c, 0x29, 0xd6, 0x99, 0x0d};
  // u_int8_t sender_ip[4] = ip;
  uint8_t arp_tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  // u_int8_t target_ip[4] = {0xc0, 0xa8, 0x50, 0x81};

  // Copy to arp struct
  arp->ea_hdr.ar_hrd = htons(ar_hrd);
  arp->ea_hdr.ar_pro = htons(ar_pro);
  arp->ea_hdr.ar_hln = ar_hln;
  arp->ea_hdr.ar_pln = ar_pln;
  arp->ea_hdr.ar_op = htons(ar_op);
  memcpy(arp->arp_sha, hwaddr, sizeof(hwaddr));
  memcpy(arp->arp_spa, sip, sizeof(sip));
  // memcpy(arp->sender_ip, sender_ip, sizeof(sender_ip));
  memcpy(arp->arp_tha, arp_tha, sizeof(arp_tha));
  // memcpy(arp->arp_tha, target_mac, sizeof(target_mac));
  memcpy(arp->arp_tpa, tip, sizeof(tip));
  // memcpy(arp->target_ip, target_ip, sizeof(target_ip));

  // Print
  // printf("arp->ea_hdr.ar_hrd: %04x\n", arp->ea_hdr.ar_hrd);
  // printf("arp->ea_hdr.ar_pro: %04x\n", arp->ea_hdr.ar_pro);
  // printf("arp->ea_hdr.ar_hln: %02x\n", arp->ea_hdr.ar_hln);
  // printf("arp->ea_hdr.ar_pln: %02x\n", arp->ea_hdr.ar_pln);
  // printf("arp->ea_hdr.ar_op: %04x\n", arp->ea_hdr.ar_op);
  // cout << "arp->arp_sha: ";
  // printMAC(arp->arp_sha, 6);
  // cout << "arp->arp_spa: ";
  // printMAC(arp->arp_spa, 4);
  // cout << "arp->arp_tha: ";
  // printMAC(arp->arp_tha, 6);
  // cout << "arp->arp_tpa: ";
  // printMAC(arp->arp_tpa, 4);
}

int main(int argc, char* argv[]){
  char* device = argv[1];
  char* s_ip_addr = argv[2];
  char* t_ip_addr = argv[3];
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t *pcd;
  int i = 0;

  // Get ip address
  u_int8_t s_ip[4];
  u_int8_t t_ip[4];
  get_ip(s_ip_addr, s_ip);
  get_ip(t_ip_addr, t_ip);
  printf("%02x %02x %02x %02x\n",s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
  printf("%02x %02x %02x %02x\n",t_ip[0], t_ip[1], t_ip[2], t_ip[3]);

  // Get my Mac Address
  uint8_t hwaddr[6];
  get_mymac(hwaddr, device);

  // Get target Mac Address
  uint8_t target_mac[6];
  get_targetmac(target_mac);

  // Allocate as much as the header size.
  struct ether_header ether;
  memset(&ether, 0, sizeof(struct ether_header));
  struct ether_arp arp;
  memset(&arp, 0, sizeof(struct ether_arp));

  // Open the pcap
  if((pcd = pcap_open_live(device, BUFSIZ, 1, 1, err_buf)) == NULL){
    perror(err_buf);
    exit(1);
  }

  // Make ethernet header
  make_ether(&ether, hwaddr, target_mac);

  // Make ARP header
  make_arp(&arp, s_ip, t_ip, hwaddr, target_mac);

  // Allocate as much as the packet size.
  uint8_t packet[42];
  memset(packet, 0, sizeof(packet));
  int size_of_packet = sizeof(packet);
  int length = 0;

  // Copy the ethernet header
  memcpy(&packet, &ether, sizeof(ether));
  length += sizeof(ether);
  // printMAC(packet, 14);

  // Copy the arp header
  memcpy(packet+length, &arp, sizeof(arp));
  printMAC(packet, sizeof(packet));

  // Send the packet
  i = 0;
  while(1) {
    cout << "send packet: " << i << endl;
    pcap_sendpacket(pcd, packet, size_of_packet);
    i += 1;
    usleep(100000);
  }
}
