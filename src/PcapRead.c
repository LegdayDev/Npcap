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
#pragma pack(pop)

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

#define LINE_LEN 16

/*
	dispatcher_handler() : 디스크에 있는 오프라인 패킷데이터를 캡쳐하여 처리하고 출력하는 함수

	// 캡쳐된 패킷의 메타데이터 구조체
	struct pcap_pkthdr {
		struct timeval ts;	// 패킷 캡쳐 시간
		bpf_u_int32 caplen; // 캡처된 패킷 데이터의 길이
		bpf_u_int32 len;	// 실제 패킷의 전체 길이(네트워크에서 전달된 원본 패킷 크기)
	};
*/
void dispatcher_handler(
	u_char* temp1, // 사용자 데이터를 전달받는 포인터(현재 예제에서는 NULL 을 넘기기 때문에 null)
	const struct pcap_pkthdr* header,  // 캡쳐된 패킷의 헤더(메타 데이터)를 담고 있는 구조체
	const u_char* pkt_data)            // 캡쳐된 패킷의 실제 내용(바이너리 데이터)
{
	u_int i = 0;

	// 패킷의 캡쳐시간(s, ms)과 패킷의 전체 길이 출력
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	// 패킷을 EtherHeader 로 강제 형변환
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	// EtherHeader 의 출발지,목적지,Type 출력
	printf(
		"SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
		"DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
		pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
		pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
		pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
		pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
		htons(pEther->type));

	// 패킷 데이터를 16 진수로 출력
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n"); // 패킷 끝에 도달하면 줄 바꿈후 종료
	}

	printf("\n\n");
}

int main(int argc, char** argv)
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/*
	pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) : 지정된 개수만큼의 패킷을 캡쳐하여 루프 실행
		- p : pcap_open_offline() or pcap_open_live() 로 얻은 cap 핸들, 아래 예제는 fp 를 사용하기 때문에 실제 오프라인 PCAP 파일을 가리킨다.
		- cnt : 캡쳐할 패킷의 개수를 지정, 0 은 무한정을 의미 즉 파일의 끝까지 패킷을 처리하겠다는 뜻
		- pcap_handler callback : 패킷이 캡쳐될 때 호출되는 콜백 함수
		- user : 사용자 데이터로, 콜백 함수에 전달된다
	*/
	if ((fp = pcap_open_offline(
		"C:\\SampleTraces\\ip-fragments.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"C:\\SampleTraces\\ip-fragments.pcap");
		return -1;
	}

	/*
	pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) : 지정된 개수만큼의 패킷을 캡쳐하여 루프 실행
		- p : pcap_open_offline() or pcap_open_live() 로 얻은 cap 핸들, 아래 예제는 fp 를 사용하기 때문에 실제 오프라인 PCAP 파일을 가리킨다.
		- cnt : 캡쳐할 패킷의 개수를 지정, 0 은 무한정을 의미 즉 파일의 끝까지 패킷을 처리하겠다는 뜻
		- pcap_handler callback : 패킷이 캡쳐될 때 호출되는 콜백 함수
		- user : 사용자 데이터로, 콜백 함수에 전달된다
	*/
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	pcap_close(fp);
	return 0;
}



