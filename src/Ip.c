#include <stdio.h>    // ǥ�� ������� ���� ���
#include <pcap.h>     // ��Ŷ ĸó�� ���� PCAP ���̺귯�� ���
#include <time.h>     // �ð� ���� �Լ��� ���� ���
#include <windows.h>  // CLion ������ Windows ������ ���� �⺻������� �ڵ����� �������� �ʱ� ������ �߰������ ��.
#include <WinSock2.h> // Windows ���� ���α׷����� ���� ��� (�ݵ�� windows.h �ڿ� �����ؾ� ��)
#include <tchar.h>    // �����ڵ�/MBCS ȣȯ�� ���� TEXT ��ũ�� ���� ���

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")


#pragma pack(push, 1) // �޸� ���Ĺ�� ����
typedef struct EtherHeader { // Ethernet ��� ����ü ����
	unsigned char dstMac[6]; // ������ �ּ�
	unsigned char srcMac[6]; // ����� �ּ�
	unsigned short type;     // �������� �������� �м�
} EtherHeader;

typedef struct IpHeader {       // IP ��� ����ü ����
	unsigned char verIhl;       // Version(IPv4 or IPV6) �� IHL(�������)
	unsigned char tos;          // ��Ŷ�� ���� ǰ��
	unsigned short length;      // ��Ŷ�� ����
	unsigned short id;          // ��Ŷ ����ȭ �� Ȱ���ϴ� �ʵ�
	unsigned short fragOffset;  // ����ȭ ���� �ʵ�
	unsigned char ttl;          // IP��Ŷ�� ��Ʈ��ũ�� ���� ���޵� �� �ִ� �ִ� �ð��� �����ϴ� �ʵ�
	unsigned char protocol;     // ���� ���� �������� �ĺ��ϴ� �ʵ�
	unsigned short checksum;    // IP ��� ���Ἲ ���� �ʵ�
	unsigned char srcIp[4];     // ����� �ּ�
	unsigned char dstIp[4];     // ������ ����
} IpHeader;
#pragma pack(pop) // �޸� ���Ĺ�� ����

/*
 * LoadNpcapDlls() : Npcap DLL ���ϵ��� �ε��ϱ� ���� �Լ�
 */
BOOL LoadNpcapDlls()
{
	// Windows �ý��� ���丮 ��θ� ������ ���� ����
	// _TCHAR�� �����ڵ�/��Ƽ����Ʈ ȣȯ�� ���� ��ũ�� Ÿ��
	_TCHAR npcap_dir[512];
	UINT len;

	// Windows �ý��� ���丮 ��θ� ������ (���� C:\Windows\System32)
	// 480�� ���߿� "\Npcap" ���ڿ��� ���� ������ ����� ����
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		// �ý��� ���丮 ��θ� �������µ� �����ϸ� ���� ���
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}

	// �ý��� ���丮 ��� �ڿ� "\Npcap" �߰�
	// _T ��ũ�δ� ���ڿ��� �����ڵ�/��Ƽ����Ʈ ȣȯ �������� ��ȯ
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));

	// DLL �˻� ��ο� Npcap ���丮 �߰�
	// SetDllDirectory�� �����ϸ� (0�� ��ȯ�ϸ�) ���� ó��
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	// ��� ������ ���������� �Ϸ�Ǹ� TRUE ��ȯ
	return TRUE;
}


/*
 * packet_handler() : ��Ŷ ĸ�� �ݹ� �Լ�, ��Ŷ�� ĸ�ĵ� ������ ȣ���.
 *
 * u_char* param : ����� ���� �Ű� ����(�ݹ� �� �Ѱ���)
 * pacp_pkthdr* header : ��Ŷ�� ��Ÿ������(�ݹ� �� �Ѱ���)
 * u_char* pkt_data : ��ü ĸ�ĵ� ��Ŷ ������
 */
void packet_handler(
	u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	// ��Ŷ �����͸� Ehternet �������ü�� ����ȯ
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	// Ethernet ����� type �ʵ尡 0x0008(IP��������)�� �ƴϸ� �Լ� ����
	if (pEther->type != 0x0008)
		return;

	// Ethernet ��� ���� Payload(IP���)�� ���� ����ȯ, Ethernet ����� ���̸�ŭ ���� �� ����ȯ
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	// IP ����(���� 4��Ʈ)�� IHL(���� 4��Ʈ, ��� ����), ��ü ��Ŷ ���� ���
	printf("IPv%d, IHL: %d, Total length: %d\n",
		(pIpHeader->verIhl & 0xF0) >> 4, // IP ���� ���� (���� 4��Ʈ)
		(pIpHeader->verIhl & 0x0F) * 4,  // IHL ���� (���� 4��Ʈ) * 4����Ʈ
		ntohs(pIpHeader->length));       // ��Ʈ��ũ ����Ʈ ������ ȣ��Ʈ ����Ʈ ������ ��ȯ

	// TTL(Time To Live), �������� ��ȣ, üũ�� ���
	printf("TTL: %d, Protocol: %02X, Checksum: %04X\n",
		pIpHeader->ttl,                // ��Ŷ�� ����
		pIpHeader->protocol,           // ���� ���� ��������
		ntohs(pIpHeader->checksum));   // IP ��� üũ��

	// ����� IP�� ������ IP�� ������ ������ �������� ���
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3]
	);
}

int main()
{
    pcap_if_t* alldevs;  // ��Ʈ��ũ ��ġ ���
    pcap_if_t* d;        // ���� ��Ʈ��ũ ��ġ
    int inum;            // ������ ��ġ ��ȣ
    int i = 0;
    pcap_t* adhandle;    // ��Ŷ ĸó �ڵ�
    char errbuf[PCAP_ERRBUF_SIZE];  // ���� ����

    // Npcap DLL �ε�
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap�� �ε��� �� �����ϴ�.\n");
        exit(1);
    }

    // ��Ʈ��ũ ��ġ ����� ��������
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs���� ���� �߻�: %s\n", errbuf);
        exit(1);
    }

    // ��Ʈ��ũ ��ġ ��� ���
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);  // ��ġ ��ȣ�� �̸� ���
        if (d->description)
            printf(" (%s)\n", d->description);  // ��ġ ���� ���
        else
            printf(" (���� ����)\n");  // ������ ���� ���
    }

    if (i == 0)  // ��ġ�� �ϳ��� ������ ���� �޽��� ���
    {
        printf("\n�������̽��� �����ϴ�! Npcap�� ��ġ�Ǿ� �ִ��� Ȯ���ϼ���.\n");
        return -1;
    }

    // ����ڿ��� ��ġ ���� ��û
    printf("�������̽� ��ȣ�� �Է��ϼ��� (1-%d):", i);
    scanf_s("%d", &inum);  // ����ڷκ��� �������̽� ��ȣ �Է�

    if (inum < 1 || inum > i)  // ��ȿ���� ���� ��ȣ �Է� �� ���� �޽��� ���
    {
        printf("\n�������̽� ��ȣ�� ������ ������ϴ�.\n");
        pcap_freealldevs(alldevs);  // ��ġ ��� ����
        return -1;
    }

    // ������ ��ġ�� �̵�
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // ��ġ ����
    if ((adhandle = pcap_open_live(d->name,  // ��ġ �̸�
        65536,          // ĸó�� ��Ŷ ũ�� (��ü ��Ŷ ĸó)
        1,              // ���ι̽�ť� ��� (1�̸� ���ι̽�ť� ��� Ȱ��ȭ)
        1000,           // Ÿ�Ӿƿ� (�и��� ����)
        errbuf          // ���� ����
    )) == NULL)
    {
        fprintf(stderr, "\n����͸� �� �� �����ϴ�. %s�� Npcap���� �������� �ʽ��ϴ�.\n", d->name);
        pcap_freealldevs(alldevs);  // ��ġ ��� ����
        return -1;
    }

    printf("\n%s���� ��Ŷ�� ���� ��...\n", d->description);  // ��Ŷ ĸó ���� �޽��� ���

    pcap_freealldevs(alldevs);  // ��ġ ����� �� �̻� �ʿ� �����Ƿ� ����

    // ��Ŷ ĸó ����
    pcap_loop(adhandle, 0, packet_handler, NULL);  // ��Ŷ�� ������ ������ packet_handler ȣ��

    pcap_close(adhandle);  // ��Ŷ ĸó �ڵ� �ݱ�

    return 0;
}
