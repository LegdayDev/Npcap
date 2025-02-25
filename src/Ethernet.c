#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <windows.h>  // TODO : CLion 에서는 Windows 개발을 위한 기본헤더들을 자동으로 포함하지 않기 때문에 추가해줘야 함.

/*
    #prgma comment(lib, ..)
    외부 라이브러리를 명시적으로 지정할 필요 없이 컴파일러가 자동으로 라이브러리를 연결시키는 지시어이다.
*/
#pragma comment(lib, "wpcap")  // Npcap or WinPacap 라이브러리 링크
#pragma comment(lib, "ws2_32") // Windows Sockets2 라이브러리 링크

#include <tchar.h>
#include <WinSock2.h>


/*
    기본적으로 C컴파일러는 데이터 타입에 맞게 메모리정렬을 최적화한다.
    #pragma pack(push,1)는 이를 무시하고 각 멤버 변수들이 1바이트 단위로 메모리 상에 배치하도록 한다.
    즉, 아래 구조체는 dstMac[6]=6Byte, srcMac[6]=6Byte, type
*/
#pragma pack(push, 1)  // 구조체 메모리 정렬을 1바이트로 설정
typedef struct EtherHeader {
    unsigned char dstMac[6];  // 목적지 MAC 주소
    unsigned char srcMac[6];  // 출발지 MAC 주소
    unsigned short type;      // 이더넷 타입 (예: IP, ARP 등)
} EtherHeader;
#pragma pack(pop)  // 구조체 메모리 정렬을 원래대로 복구

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

// 패킷 수신 후 처리하는 콜백 함수
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;  // 로컬 시간 구조체
    char timestr[16];  // 시간을 저장할 문자열
    time_t local_tv_sec;  // 패킷의 timestamp를 저장할 변수

    /* timestamp를 사람이 읽을 수 있는 형식으로 변환 */
    local_tv_sec = header->ts.tv_sec;  // 패킷 수신 시간을 초 단위로 가져옴
    localtime_s(&ltime, &local_tv_sec);  // 초 단위를 로컬 시간으로 변환
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);  // 시간 문자열 형식 지정

    EtherHeader* pEther = (EtherHeader*)pkt_data;  // 패킷 데이터를 EtherHeader 구조체로 변환

    // 패킷 정보 출력: 시간, 길이, MAC 주소, 이더넷 타입
    printf("%s,%.6d len:%d, "
        "SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
        "DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
        timestr, header->ts.tv_usec, header->len,
        pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
        pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
        pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
        pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
        ntohs(pEther->type));  // 이더넷 타입은 네트워크 바이트 순서에서 호스트 바이트 순서로 변환
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
