#ifndef SMB_CAPTURE_H
#define SMB_CAPTURE_H

#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <errno.h>

#define SMB2_HEADER_SIZE 64

#define SMB_PORT 445

extern char *g_output_dir;

// NetBIOS Session Service 헤더
typedef struct s_netbios_header {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
} __attribute__((packed)) t_netbios_header;

// SMB2 헤더 구조체
typedef struct s_smb2_header {
	uint8_t protocol_id[4];     // 0xFE 'S' 'M' 'B' (0xFE534D42)
	uint16_t struct_size;       // 64
	uint16_t credit_charge;
	uint32_t status;
	uint16_t command;
	uint16_t credit_req_resp;
	uint32_t flags;
	uint32_t next_command;
	uint64_t message_id;
	uint32_t reserved;
	uint32_t tree_id;
	uint64_t session_id;
	uint8_t signature[16];
} __attribute__((packed)) t_smb2_header;

// SMB2 명령어 코드
#define SMB2_NEGOTIATE          0x0000
#define SMB2_SESSION_SETUP      0x0001
#define SMB2_LOGOFF             0x0002
#define SMB2_TREE_CONNECT       0x0003
#define SMB2_TREE_DISCONNECT    0x0004
#define SMB2_CREATE             0x0005
#define SMB2_CLOSE              0x0006
#define SMB2_FLUSH              0x0007
#define SMB2_READ               0x0008
#define SMB2_WRITE              0x0009
#define SMB2_LOCK               0x000A
#define SMB2_IOCTL              0x000B
#define SMB2_CANCEL             0x000C
#define SMB2_ECHO               0x000D
#define SMB2_QUERY_DIRECTORY    0x000E
#define SMB2_CHANGE_NOTIFY      0x000F
#define SMB2_QUERY_INFO         0x0010
#define SMB2_SET_INFO           0x0011

// TCP 스트림 순서 노드
typedef struct s_seg_node {
	uint32_t seq;
	size_t len;
	uint8_t *data;
	struct s_seg_node *next;
} t_seg_node;

typedef struct s_tcp_stream_buf {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t next_seq;
	int has_seq;
	uint8_t *buf;
	size_t len;
	size_t cap;
	size_t limit;
	time_t last_seen;
	t_seg_node *ooo;
	struct s_tcp_stream_buf *next;
} t_tcp_stream_buf;


// pending 구조체
typedef struct s_pending_create {
	uint64_t session_id;
	uint64_t message_id;
	char filename[256];
	struct s_pending_create *next;
} t_pending_create;

typedef struct s_pending_read {
	uint64_t session_id;
	uint64_t message_id;
	uint8_t file_id[16];
	uint64_t offset;
	uint32_t length;
	struct s_pending_read *next;
} t_pending_read;


// SMB2 Create Request (간소화)
typedef struct s_smb2_create_req {
	uint16_t struct_size;
	uint8_t security_flags;
	uint8_t requested_oplock_level;
	uint32_t impersonation_level;
	uint64_t smb_create_flags;
	uint64_t reserved;
	uint32_t desired_access;
	uint32_t file_attributes;
	uint32_t share_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t create_contexts_offset;
	uint32_t create_contexts_length;
} __attribute__((packed)) t_smb2_create_req;

// SMB2 Create Response
typedef struct s_smb2_create_resp {
	uint16_t struct_size;
	uint8_t oplock_level;
	uint8_t flags;
	uint32_t create_action;
	uint64_t creation_time;
	uint64_t last_access_time;
	uint64_t last_write_time;
	uint64_t change_time;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
	uint32_t reserved2;
	uint8_t file_id[16];
} __attribute__((packed)) t_smb2_create_resp;

// SMB2 Write Request
typedef struct s_smb2_write_req {
	uint16_t struct_size;
	uint16_t data_offset;
	uint32_t length;
	uint64_t offset;
	uint8_t file_id[16];
	uint32_t channel;
	uint32_t remaining_bytes;
	uint16_t write_channel_info_offset;
	uint16_t write_channel_info_length;
	uint32_t flags;
} __attribute__((packed)) t_smb2_write_req;

// SMB2 Read Response
typedef struct s_smb2_read_resp {
	uint16_t struct_size;
	uint8_t data_offset;
	uint8_t reserved;
	uint32_t data_length;
	uint32_t data_remaining;
	uint32_t reserved2;
} __attribute__((packed)) t_smb2_read_resp;

// SMB2 Read Request
typedef struct s_smb2_read_req {
	uint16_t struct_size;
	uint8_t padding;
	uint8_t flags;
	uint32_t length;
	uint64_t offset;
	uint8_t file_id[16];
	uint32_t minimum_count;
	uint32_t channel;
	uint32_t remaining_bytes;
	uint16_t read_channel_info_offset;
	uint16_t read_channel_info_length;
} __attribute__((packed)) t_smb2_read_req;

// 파일 전송 추적 구조체
typedef struct s_file_transfer {
	uint8_t file_id[16];
	char filename[256];
	uint64_t file_size;
	uint64_t bytes_received;
	uint8_t *file_data;
	uint32_t data_capacity;
	time_t start_time;
	int is_complete;
	struct s_file_transfer *next;
} t_file_transfer;

// 함수 선언
void signal_handler(int signum);
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_smb_packet(const u_char *smb_data, int smb_len, const struct pcap_pkthdr *header);
void handle_smb2_create(const t_smb2_header *smb_hdr, const u_char *data, int len);
void handle_smb2_write(const t_smb2_header *smb_hdr, const u_char *data, int len);
void handle_smb2_read(const t_smb2_header *smb_hdr, const u_char *data, int len);
t_file_transfer* find_file_transfer(const uint8_t *file_id);
t_file_transfer* create_file_transfer(const uint8_t *file_id, const char *filename);
int append_file_data(t_file_transfer *transfer, const uint8_t *data, uint32_t len, uint64_t offset);
void save_file(t_file_transfer *transfer);
void cleanup_transfers();
char* extract_filename_from_create(const u_char *data, int len, uint16_t name_offset, uint16_t name_length);
void handle_smb2_close(const t_smb2_header *smb_hdr, const u_char *data, int len);
int set_output_directory(const char *path);

#endif /* SMB_CAPTURE_H */
