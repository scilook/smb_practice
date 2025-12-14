#include "smb_capture.h"

extern pcap_t *g_handle;

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = NULL;
	char device_buf[256];
	struct bpf_program fp;
	bpf_u_int32 net, mask;
	
	signal(SIGINT, signal_handler);
	
	printf("=== SMB2 Live File Capture Tool ===\n");
	printf("This tool captures and reassembles files transferred via SMB protocol\n\n");

	// 저장 경로 설정
	if (argc > 2) {
		if (set_output_directory(argv[2]) != 0) {
			return 1;
		}
	}
	else
		g_output_dir = getcwd(NULL, 0);
	printf("Output directory: %s\n", g_output_dir);
	
	// 네트워크 인터페이스 선택
	if (argc > 1) {
		device = argv[1];
		printf("Using specified device: %s\n", device);
	}
	else {
		pcap_if_t *alldevs;
		if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
			fprintf(stderr, "Error finding device: %s\n", errbuf);
			fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
			return 1;
		}
		strncpy(device_buf, alldevs->name, sizeof(device_buf) - 1);
		device_buf[sizeof(device_buf) - 1] = '\0';
		device = device_buf;
		printf("Using default device: %s\n", device);
		pcap_freealldevs(alldevs);
	}
	
	// 네트워크 정보 가져오기
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Warning: Could not get network info: %s\n", errbuf);
		net = 0;
		mask = 0;
	}
	
	// 캡처 세션 열기
	g_handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
	if (g_handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
		fprintf(stderr, "Try running with sudo/root privileges\n");
		return 1;
	}
	
	// BPF 필터 설정 (SMB 포트 445)
	char filter_exp[] = "tcp port 445";
	if (pcap_compile(g_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(g_handle));
		pcap_close(g_handle);
		return 1;
	}
	
	if (pcap_setfilter(g_handle, &fp) == -1) {
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(g_handle));
		pcap_freecode(&fp);
		pcap_close(g_handle);
		return 1;
	}
	
	printf("Filter: %s\n", filter_exp);
	printf("Listening for SMB traffic...\n");
	printf("Press Ctrl+C to stop capture\n\n");
	
	// 패킷 캡처 시작
	pcap_loop(g_handle, -1, pcap_callback, NULL);
	
	// 정리
	printf("\n[CLEANUP] Stopping capture and saving files...\n");
	pcap_freecode(&fp);
	pcap_close(g_handle);
	cleanup_transfers();
	
	printf("[DONE] Capture session ended\n");
	
	return 0;
}
