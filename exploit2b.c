#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define MAX_ENTRIES 16

int plife = 99999, rlife = 4096, llife = 2048, reach = 0, trans = 0, dlife = 4096, cnt, to_send = 256, flags = 0, myoff = 14;
char *frbuf, *frbuf2, *frint, buf3[1232];
int frbuflen, frbuf2len, type = NXT_ICMP6, prio = 2;
unsigned char *frip6, *frmac;
thc_ipv6_hdr *frhdr = NULL;
thc_ipv6_hdr *frhdr2 = NULL;



void send_rs_reply(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *pkt = NULL, *dstmac = (unsigned char *) data + 6, *dst = (unsigned char *) data + 14 + 8, *ipv6hdr = (unsigned char *) (data + 14);
  int pkt_len = 0, i;

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_ROUTERSOL || header->caplen < 14 + 40 + 2)
    return;
  if ((pkt = thc_create_ipv6(frint, PREFER_LINK, &pkt_len, frip6, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return;
  if (thc_generate_and_send_pkt(frint, frmac, dstmac, pkt, &pkt_len) < 0)
    return;

  pkt = thc_destroy_packet(pkt);
}


int main(int argc, char *argv[]) {
  char *interface, mac[16] = "", dmac[16] = "";
  unsigned char *routerip6, *mac6 = NULL, *ip6 = NULL;
  unsigned char buf[512], *ptr, buf2[6], buf4[6], string[] = "ip6 and icmp6 and dst ff02::2";
  unsigned char rbuf[MAX_ENTRIES + 1][17], pbuf[MAX_ENTRIES + 1][17], *dbuf[MAX_ENTRIES + 1];
  unsigned char *dst = thc_resolve6("ff02::1");
  unsigned char *dstmac = thc_get_multicast_mac(dst);
  unsigned char *dns = NULL;
  int size, mtu = 0, i, j, k, l, m, n, rcnt = 0, pcnt = 0, dcnt = 0, sent = 0;
  unsigned char *pkt = NULL, *pkt2 = NULL, *searchlist = NULL;
  int pkt_len = 0, pkt2_len = 0;
  pcap_t *p;




  // setting
  memset(rbuf, 0, sizeof(rbuf));
  memset(mac, 0, sizeof(mac));


  llife = atoi(argv[2]);
  ip6 = thc_resolve6(argv[1]);
  ip62 = thc_resolve6(argv[3]);
  llife2 = atoi(argv[4]);



  interface = "eth0";
  if (mtu == 0)
    mtu = thc_get_mtu(interface);
  if (mac6 == NULL)
    if ((mac6 = thc_get_own_mac(interface)) == NULL) {
      fprintf(stderr, "Error: invalid interface %s\n", interface);
      exit(-1);
    }
  if (ip6 == NULL)
    if ((ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK)) == NULL) {
      fprintf(stderr, "Error: ipv6 is not enabled on interface %s\n", interface);
      exit(-1);
    }

  frint = interface;
  frip6 = ip6;
  frmac = mac6;
  frbuf = buf;
  frbuf2 = buf2;
  frbuf2len = sizeof(buf2);

  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  if (llife > 0xffff)
    llife = 0xffff;
  llife = (llife | 0xff000000);
  if (prio == 2)
    llife = (llife | 0x00080000);
  else if (prio == 0)
    llife = (llife | 0x00180000);
  else if (prio != 1)
    llife = (llife | 0x00100000);
  
  llife = (llife | (flags << 16));

  buf[0] = reach / 16777216;
  buf[1] = (reach % 16777216) / 65536;
  buf[2] = (reach % 65536) / 256;
  buf[3] = reach % 256;
  buf[4] = trans / 16777216;
  buf[5] = (trans % 16777216) / 65536;
  buf[6] = (trans % 65536) / 256;
  buf[7] = trans % 256;

  // option mtu
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  i = 16;

  // mac address option
  buf[i++] = 1;
  buf[i++] = 1;
  memcpy(buf + i, mac6, 6);
  i += 6;

  // option prefix, put all in
  if (pcnt > 0)
    for (j = 0; j < pcnt; j++) {
      buf[i++] = 3;
      buf[i++] = 4;
      buf[i++] = pbuf[j][0];    // prefix length
      buf[i++] = 128 + 64;
      buf[i++] = plife / 16777216;
      buf[i++] = (plife % 16777216) / 65536;
      buf[i++] = (plife % 65536) / 256;
      buf[i++] = plife % 256;
      buf[i++] = (plife / 2) / 16777216;
      buf[i++] = ((plife / 2) % 16777216) / 65536;
      buf[i++] = ((plife / 2) % 65536) / 256;
      buf[i++] = (plife / 2) % 256;
      i += 4;                   // + 4 bytes reserved
      memcpy(&buf[i], (char *) &pbuf[j][1], 16);
      i += 16;
    }
  // route option, put all in
  if (rcnt > 0)
    for (j = 0; j < rcnt; j++) {
      buf[i++] = 0x18;          // routing entry option type
      buf[i++] = 0x03;          // length 3 == 24 bytes
      buf[i++] = rbuf[j][0];    // prefix length
      if (prio == 2)
        buf[i++] = 0x08;          // priority, highest of course
      else if (prio == 1)
        buf[i++] = 0x00;
      else if (prio == 0)
        buf[i++] = 0x18;
      else
        buf[i++] == 0x10;
      buf[i++] = rlife / 16777216;
      buf[i++] = (rlife % 16777216) / 65536;
      buf[i++] = (rlife % 65536) / 256;
      buf[i++] = rlife % 256;
      memcpy((char *) &buf[i], (char *) &rbuf[j][1], 16);       // network
      i += 16;
    }
  // dns option
  if (dcnt > 0)
    for (j = 0; j < dcnt; j++) {
      buf[i++] = 0x19;          // dns option type
      buf[i++] = 0x03;          // length
      i += 2;                   // reserved
      buf[i++] = dlife / 16777216;
      buf[i++] = (dlife % 16777216) / 65536;
      buf[i++] = (dlife % 65536) / 256;
      buf[i++] = dlife % 256;
      memcpy(buf + i, dbuf[j], 16);     // dns server
      i += 16;
    }
    
  // dns searchlist option
  if (searchlist != NULL) {
    buf[i] = 31;
    buf[i + 4] = dlife / 16777216;
    buf[i + 5] = (dlife % 16777216) / 65536;
    buf[i + 6] = (dlife % 65536) / 256;
    buf[i + 7] = dlife % 256;
    if (searchlist[strlen(searchlist) - 1] == '.')
      searchlist[strlen(searchlist) - 1] = 0;
    m = 0;
    while ((ptr = strstr(searchlist, ".,")) != NULL) {
      m = strlen(ptr);
      for (l = 1; l < m; l++)
        ptr[l - 1] = ptr[l];
      ptr[m - 1] = 0;
    }
    l = 0;
    m = 0;
    j = strlen(searchlist);
    do {
      k = 0;
      ptr = index(&searchlist[l], '.');
      if (ptr == NULL || (index(&searchlist[l], ',') != NULL && (char*)ptr > (char*)index(&searchlist[l], ','))) {
        k = 1;
        ptr = index(&searchlist[l], ',');
      }
      if (ptr != NULL)
        *ptr = 0;
      n = strlen(&searchlist[l]);

      buf[i + 8 + m] = n;
      memcpy(&buf[i + 8 + m + 1], &searchlist[l], n);

      if (ptr == NULL)
        l = j;
      else
        l += 1 + n;

      m += 1 + n;

      if (k || ptr == NULL)
        m++; // end of domain entry
    } while (l < j && ptr != NULL);
    if (m % 8 > 0)
      m = ( (m / 8) + 1 ) * 8;
    buf[i + 1] = m/8 + 1;
    i += m + 8;
  }

  frbuflen = i;

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, ip6, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;

  if ((pkt2 = thc_create_ipv6(interface, PREFER_LINK, &pkt2_len, ip62, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;

  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, llife, buf, i, 0) < 0)
    return -1;

  if (thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0)
    return -1;
  
  frhdr = (thc_ipv6_hdr *) pkt;
  frhdr2 = (thc_ipv6_hdr *) pkt2;

  p = thc_pcap_init(interface, string));

  printf("Advertising...%s with a life time %s\n", argv[1], argv[2]);
  while (sent < to_send || to_send > 255) {
    thc_send_pkt(interface, pkt, &pkt_len);
    while (thc_pcap_check(p, (char *) send_rs_reply, NULL) > 0);
    sent++;
    if (sent != to_send || to_send > 255)
      sleep(5);
  }
  return 0; // never reached
}
