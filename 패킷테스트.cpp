#include "pcap.h"
#include <stdio.h>

#define WPCAP
#define HAVE_REMOTE

dsadsa

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
typedef struct ip_header
{
	u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
	u_char tos; // Type of service 
	u_short tlen; // Total length 
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;   // Source port
	u_short dport;   // Destination port
	u_short len;   // Datagram length
	u_short crc;   // Checksum
}udp_header;

/* eternet header */
struct ether_header
{
	u_char dst_host[6];
	u_char src_host[6];
	u_short frame_type;
}ether_header;

typedef struct tcp_header
{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int seqnum; // Sequence Number
	u_int acknum; // Acknowledgement number
	u_char hlen; // Header length
	u_char flags; // packet flags
	u_short win; // Window size
	u_short crc; // Header Checksum
	u_short urgptr; // Urgent pointer...still don't know what this is...
}tcp_header;

/* 패킷이 캡처 됬을때, 호출되는 콜백 함수 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

char link[100];
char woonbe[100];
int img_ip[4];
int img_pt;

FILE *fp = NULL;
int main()
{
	
	fp=fopen("test.txt","a");
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	//필터룰 지정 
	char *filter = "port 80";
	struct bpf_program fcode;
	bpf_u_int32 NetMask;

	/* 네트워크 다바이스 목록을 가져온다. */
	/* alldevs에 리스트 형태로 저장되며, 에러시 errbuf에 에러 내용 저장 */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 네트워크 다바이스명을 출력한다. */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("\n\t(%s)\n\n", d->description);
		else
			printf(" (No description available)\n");
	}

	/* 에러 처리 */
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/* 캡처할 네트워크 디바이스 선택 */
	printf("네트워크 장비 선택 : (1-%d):",i);
	scanf("%d", &inum);

	/* 입력값의 유효성 판단 */
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 장치 목록 해제 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 사용자가 선택한 장치목록 선택 */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* 실제 네트워크 디바이스를 오픈 */
	if ((adhandle= pcap_open_live(d->name, // 디바이스명
		65536,   // 최대 캡처길이 
		// 65536 -> 캡처될수 있는 전체 길이 
		1,    // 0: 자신에게 해당되는 패킷만 캡처
		// 1: 들어오는 모든 패킷 캡처
		10,   // read timeout 
		errbuf   // 에러내용 저장변수 
		)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 장치 목록 해제 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 넷마스크 지정, 이부분은 아직 잘 모르겠음 */
	NetMask=0xffffff;
	// 사용자가 정의한 필터룰 컴파일
	if(pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0)
	{
		fprintf(stderr,"\nError compiling filter: wrong syntax.\n");
		pcap_close(adhandle);
		return -3;
	}
	// 사용자가 정의한 필터룰 적용
	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter\n");
		pcap_close(adhandle);
		return -4;
	}
	/* 장치 목록 해제 */
	pcap_freealldevs(alldevs);

	/* 캡처 시작 */
	pcap_loop(adhandle,      // pcap_open_live통해 얻은 네트워크 디바이스 핸들
		100,     // 0 : 무한루프
		 // 양의정수 : 캡처할 패킷수 
		packet_handler,  // 패킷이 캡처됬을때, 호출될 함수 핸들러 
		NULL);           // 콜백함수로 넘겨줄 파라미터 

	pcap_close(adhandle);    // 네트워크 디바이스 핸들 종료

	printf("\n링크주소 : %s\n",woonbe);
	
	fclose(fp);
	printf("%s",link);
	return 0;
}

/* 패킷이 캡처 됬을때, 호출되는 콜백 함수 */
void packet_handler(u_char *param,                    //파라미터로 넘겨받은 값 
	const struct pcap_pkthdr *header, //패킷 정보 
	const u_char *pkt_data)           //실제 캡처된 패킷 데이터
{
	int i;

	// 아이피, 포트를 구하기 위한 변수
	ip_header *ih;
	udp_header *uh;
	tcp_header *th;
	u_int ip_len;

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data + 14); //length of ethernet header
	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);



	if(ih->proto==6)
	{
		th = (tcp_header*) (ih + ip_len);
		printf("TCP\n");
	}
	else if(ih->proto==17)
	{
		uh=(udp_header*) (uh + ip_len);
		printf("UDP\n");
	}
	th->dport;

	//printf("목적지 %d.%d.%d.%d\n",ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
	int token=0,j=0;
	
	/* Print the packet */
	for (i=1; (i < header->caplen + 1 ) ; i++)
	{
		if(token==1){	
			//link[j++] = pkt_data[i-1];
			printf("%.2x ", pkt_data[i-1]);
			fputc(pkt_data[i-1] ,fp);
			if ( (i % 16) == 0) printf("\n");
	
			//printf("%c",pkt_data[i-1]);
		}
		if(pkt_data[i-5]=='P' && pkt_data[i-4] == 'O' && pkt_data[i-3] == 'S' && pkt_data[i-2] == 'T')
		{
			token=1;
		}
		//	printf("%.2x ", pkt_data[i-1]);
		
	}

	printf("\n\n");
}