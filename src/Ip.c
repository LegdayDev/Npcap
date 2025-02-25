#include <stdio.h>    // 표준 입출력을 위한 헤더
#include <pcap.h>     // 패킷 캡처를 위한 PCAP 라이브러리 헤더
#include <time.h>     // 시간 관련 함수를 위한 헤더
#include <windows.h>  // CLion 에서는 Windows 개발을 위한 기본헤더들을 자동으로 포함하지 않기 때문에 추가해줘야 함.
#include <WinSock2.h> // Windows 소켓 프로그래밍을 위한 헤더 (반드시 windows.h 뒤에 포함해야 함)
#include <tchar.h>    // 유니코드/MBCS 호환을 위한 TEXT 매크로 관련 헤더

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")


#pragma pack(push, 1) // 메모리 정렬방식 지정
typedef struct EtherHeader { // Ethernet 헤더 구조체 선언
	unsigned char dstMac[6]; // 목적지 주소
	unsigned char srcMac[6]; // 출발지 주소
	unsigned short type;     // 상위계층 프로토콜 분석
} EtherHeader;

typedef struct IpHeader {       // IP 헤더 구조체 선언
	unsigned char verIhl;       // Version(IPv4 or IPV6) 과 IHL(헤더길이)
	unsigned char tos;          // 패킷의 서비스 품질
	unsigned short length;      // 패킷의 길이
	unsigned short id;          // 패킷 단편화 시 활용하는 필드
	unsigned short fragOffset;  // 단편화 관련 필드
	unsigned char ttl;          // IP패킷이 네트워크를 통해 전달될 수 있는 최대 시간을 설정하는 필드
	unsigned char protocol;     // 상위 계층 프로토콜 식별하는 필드
	unsigned short checksum;    // IP 헤더 무결성 검증 필드
	unsigned char srcIp[4];     // 출발지 주소
	unsigned char dstIp[4];     // 목적지 수소
} IpHeader;
#pragma pack(pop) // 메모리 정렬방식 원복

/*
 * LoadNpcapDlls() : Npcap DLL 파일들을 로드하기 위한 함수
 */
BOOL LoadNpcapDlls()
{
	// Windows 시스템 디렉토리 경로를 저장할 버퍼 선언
	// _TCHAR는 유니코드/멀티바이트 호환을 위한 매크로 타입
	_TCHAR npcap_dir[512];
	UINT len;

	// Windows 시스템 디렉토리 경로를 가져옴 (보통 C:\Windows\System32)
	// 480은 나중에 "\Npcap" 문자열을 붙일 공간을 고려한 길이
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		// 시스템 디렉토리 경로를 가져오는데 실패하면 에러 출력
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}

	// 시스템 디렉토리 경로 뒤에 "\Npcap" 추가
	// _T 매크로는 문자열을 유니코드/멀티바이트 호환 형식으로 변환
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));

	// DLL 검색 경로에 Npcap 디렉토리 추가
	// SetDllDirectory가 실패하면 (0을 반환하면) 에러 처리
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	// 모든 과정이 성공적으로 완료되면 TRUE 반환
	return TRUE;
}


/*
 * packet_handler() : 패킷 캡쳐 콜백 함수, 패킷이 캡쳐될 떄마다 호출됨.
 *
 * u_char* param : 사용자 정의 매개 변수(콜백 시 넘겨줌)
 * pacp_pkthdr* header : 패킷의 메타데이터(콜백 시 넘겨줌)
 * u_char* pkt_data : 실체 캡쳐된 패킷 데이터
 */
void packet_handler(
	u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	// 패킷 데이터를 Ehternet 헤더구조체로 형변환
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	// Ethernet 헤더의 type 필드가 0x0008(IP프로토콜)이 아니면 함수 종료
	if (pEther->type != 0x0008)
		return;

	// Ethernet 헤더 다음 Payload(IP헤더)로 강제 형변환, Ethernet 헤더의 길이만큼 더한 후 형변환
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	// IP 버전(상위 4비트)과 IHL(하위 4비트, 헤더 길이), 전체 패킷 길이 출력
	printf("IPv%d, IHL: %d, Total length: %d\n",
		(pIpHeader->verIhl & 0xF0) >> 4, // IP 버전 추출 (상위 4비트)
		(pIpHeader->verIhl & 0x0F) * 4,  // IHL 추출 (하위 4비트) * 4바이트
		ntohs(pIpHeader->length));       // 네트워크 바이트 순서를 호스트 바이트 순서로 변환

	// TTL(Time To Live), 프로토콜 번호, 체크섬 출력
	printf("TTL: %d, Protocol: %02X, Checksum: %04X\n",
		pIpHeader->ttl,                // 패킷의 수명
		pIpHeader->protocol,           // 상위 계층 프로토콜
		ntohs(pIpHeader->checksum));   // IP 헤더 체크섬

	// 출발지 IP와 목적지 IP를 점분할 십진수 형식으로 출력
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3]
	);
}

int main()
{
    pcap_if_t* alldevs;  // 네트워크 장치 목록
    pcap_if_t* d;        // 개별 네트워크 장치
    int inum;            // 선택한 장치 번호
    int i = 0;
    pcap_t* adhandle;    // 패킷 캡처 핸들
    char errbuf[PCAP_ERRBUF_SIZE];  // 오류 버퍼

    // Npcap DLL 로드
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap을 로드할 수 없습니다.\n");
        exit(1);
    }

    // 네트워크 장치 목록을 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs에서 오류 발생: %s\n", errbuf);
        exit(1);
    }

    // 네트워크 장치 목록 출력
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);  // 장치 번호와 이름 출력
        if (d->description)
            printf(" (%s)\n", d->description);  // 장치 설명 출력
        else
            printf(" (설명 없음)\n");  // 설명이 없는 경우
    }

    if (i == 0)  // 장치가 하나도 없으면 오류 메시지 출력
    {
        printf("\n인터페이스가 없습니다! Npcap이 설치되어 있는지 확인하세요.\n");
        return -1;
    }

    // 사용자에게 장치 선택 요청
    printf("인터페이스 번호를 입력하세요 (1-%d):", i);
    scanf_s("%d", &inum);  // 사용자로부터 인터페이스 번호 입력

    if (inum < 1 || inum > i)  // 유효하지 않은 번호 입력 시 오류 메시지 출력
    {
        printf("\n인터페이스 번호가 범위를 벗어났습니다.\n");
        pcap_freealldevs(alldevs);  // 장치 목록 해제
        return -1;
    }

    // 선택한 장치로 이동
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 장치 열기
    if ((adhandle = pcap_open_live(d->name,  // 장치 이름
        65536,          // 캡처할 패킷 크기 (전체 패킷 캡처)
        1,              // 프로미스큐어스 모드 (1이면 프로미스큐어스 모드 활성화)
        1000,           // 타임아웃 (밀리초 단위)
        errbuf          // 오류 버퍼
    )) == NULL)
    {
        fprintf(stderr, "\n어댑터를 열 수 없습니다. %s는 Npcap에서 지원되지 않습니다.\n", d->name);
        pcap_freealldevs(alldevs);  // 장치 목록 해제
        return -1;
    }

    printf("\n%s에서 패킷을 수신 중...\n", d->description);  // 패킷 캡처 시작 메시지 출력

    pcap_freealldevs(alldevs);  // 장치 목록은 더 이상 필요 없으므로 해제

    // 패킷 캡처 시작
    pcap_loop(adhandle, 0, packet_handler, NULL);  // 패킷이 도착할 때마다 packet_handler 호출

    pcap_close(adhandle);  // 패킷 캡처 핸들 닫기

    return 0;
}
