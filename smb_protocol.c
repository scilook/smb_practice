#include "smb_capture.h"

extern t_file_transfer *g_transfers;

static t_tcp_stream_buf *g_tcp_streams = NULL;
static void try_process_netbios_frames(t_tcp_stream_buf *s);

static t_tcp_stream_buf* get_stream(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
	t_tcp_stream_buf *cur = g_tcp_streams;
	while (cur) {
		if (cur->src_ip == src_ip && cur->dst_ip == dst_ip && cur->src_port == src_port && cur->dst_port == dst_port) {
			return cur;
		}
		cur = cur->next;
	}

	t_tcp_stream_buf *node = (t_tcp_stream_buf*)calloc(1, sizeof(t_tcp_stream_buf));
	if (!node) {
		return NULL;
	}
	node->src_ip = src_ip;
	node->dst_ip = dst_ip;
	node->src_port = src_port;
	node->dst_port = dst_port;
	node->cap = 64 * 1024;
	node->limit = 32 * 1024 * 1024; // 32MB safety cap
	node->buf = (uint8_t*)malloc(node->cap);
	if (!node->buf) {
		free(node);
		return NULL;
	}
	node->last_seen = time(NULL);
	node->next = g_tcp_streams;
	g_tcp_streams = node;
	return node;
}

static void stream_reset(t_tcp_stream_buf *s) {
	if (!s) return;
	s->len = 0;
	s->has_seq = 0;
	while (s->ooo) {
		t_seg_node *n = s->ooo;
		s->ooo = n->next;
		free(n->data);
		free(n);
	}
}

static int stream_ensure_capacity(t_tcp_stream_buf *s, size_t needed) {
	if (!s) return -1;
	if (needed <= s->cap) return 0;
	size_t new_cap = s->cap;
	while (new_cap < needed) {
		new_cap *= 2;
		if (new_cap > (64u * 1024u * 1024u)) {
			return -1;
		}
	}
	uint8_t *new_buf = (uint8_t*)realloc(s->buf, new_cap);
	if (!new_buf) return -1;
	s->buf = new_buf;
	s->cap = new_cap;
	return 0;
}

static void try_flush_ooo(t_tcp_stream_buf *s) {
	if (!s) return;
	while (1) {
		t_seg_node **pp = &s->ooo;
		t_seg_node *match = NULL;
		while (*pp) {
			if ((*pp)->seq == s->next_seq) {
				match = *pp;
				*pp = (*pp)->next;
				break;
			}
			pp = &((*pp)->next);
		}

		if (!match) break;

		if (stream_ensure_capacity(s, s->len + match->len) != 0 || s->len + match->len > s->limit) {
			free(match->data);
			free(match);
			stream_reset(s);
			return;
		}

		memcpy(s->buf + s->len, match->data, match->len);
		s->len += match->len;
		s->next_seq += (uint32_t)match->len;
		free(match->data);
		free(match);
		try_process_netbios_frames(s);
	}
}

static void enqueue_ooo_segment(t_tcp_stream_buf *s, uint32_t seq, const uint8_t *payload, size_t payload_len) {
	if (!s || !payload || payload_len == 0) return;
	t_seg_node *node = (t_seg_node*)calloc(1, sizeof(t_seg_node));
	if (!node) return;
	node->data = (uint8_t*)malloc(payload_len);
	if (!node->data) {
		free(node);
		return;
	}
	memcpy(node->data, payload, payload_len);
	node->seq = seq;
	node->len = payload_len;

	// insert sorted by seq (ascending)
	t_seg_node **pp = &s->ooo;
	while (*pp && (*pp)->seq < seq) {
		pp = &((*pp)->next);
	}
	node->next = *pp;
	*pp = node;
}

static void try_process_netbios_frames(t_tcp_stream_buf *s) {
	if (!s) return;

	// NetBIOS Session Service header: type(1) + length(3, big-endian)
	while (s->len >= 4) {
		if (s->buf[0] != 0x00) {
			memmove(s->buf, s->buf + 1, s->len - 1);
			s->len -= 1;
			continue;
		}

		uint32_t nb_len = ((uint32_t)s->buf[1] << 16) | ((uint32_t)s->buf[2] << 8) | (uint32_t)s->buf[3];
		if (nb_len == 0 || nb_len > (16u * 1024u * 1024u)) {
			// Corrupted or unsupported length; resync.
			memmove(s->buf, s->buf + 1, s->len - 1);
			s->len -= 1;
			continue;
		}

		size_t frame_size = 4u + (size_t)nb_len;
		if (s->len < frame_size) {
			return;
		}

		process_smb_packet(s->buf, (int)frame_size, NULL);

		size_t remaining = s->len - frame_size;
		if (remaining > 0) {
			memmove(s->buf, s->buf + frame_size, remaining);
		}
		s->len = remaining;
	}
}

static void tcp_stream_push_segment(t_tcp_stream_buf *s, uint32_t seq, const uint8_t *payload, size_t payload_len) {
	if (!s || !payload || payload_len == 0) return;
	s->last_seen = time(NULL);

	if (!s->has_seq) {
		s->has_seq = 1;
		s->next_seq = seq + (uint32_t)payload_len;
		if (stream_ensure_capacity(s, payload_len) != 0 || payload_len > s->limit) {
			stream_reset(s);
			return;
		}
		memcpy(s->buf, payload, payload_len);
		s->len = payload_len;
		try_process_netbios_frames(s);
		return;
	}

	if (seq + payload_len <= s->next_seq) {
		// fully retransmitted data already processed
		return;
	}

	if (seq < s->next_seq) {
		// partial overlap; trim the seen part
		size_t overlap = (size_t)(s->next_seq - seq);
		payload += overlap;
		payload_len -= overlap;
		seq = s->next_seq;
	}

	if (seq == s->next_seq) {
		if (stream_ensure_capacity(s, s->len + payload_len) != 0 || s->len + payload_len > s->limit) {
			stream_reset(s);
			return;
		}
		memcpy(s->buf + s->len, payload, payload_len);
		s->len += payload_len;
		s->next_seq += (uint32_t)payload_len;
		try_process_netbios_frames(s);
		try_flush_ooo(s);
		return;
	}

	// seq > next_seq : out-of-order/gap, queue it
	enqueue_ooo_segment(s, seq, payload, payload_len);
	try_flush_ooo(s);
}

static int smb2_is_response(const t_smb2_header *smb_hdr) {
	return (smb_hdr->flags & 0x00000001) != 0;
}

static void print_hex_bytes(const uint8_t *bytes, int n) {
	for (int i = 0; i < n; i++) {
		printf("%02x", bytes[i]);
	}
}

static t_file_transfer* find_or_create_transfer(const uint8_t *file_id) {
	t_file_transfer *transfer = find_file_transfer(file_id);
	if (!transfer) {
		transfer = create_file_transfer(file_id, NULL);
	}
	return transfer;
}

static int smb2_extract_payload_ptr(const u_char *data, int len, uint16_t data_offset, uint32_t data_length, const uint8_t **out_ptr) {
	if (!out_ptr || !data || len <= 0 || data_offset == 0 || data_length == 0) {
		return -1;
	}

	int actual_offset = (int)data_offset - SMB2_HEADER_SIZE;
	if (actual_offset < 0 || (size_t)(actual_offset + data_length) > (size_t)len) {
		return -1;
	}

	*out_ptr = data + actual_offset;
	return 0;
}

static void log_transfer_chunk(const char *tag, const uint8_t *file_id, uint64_t offset, uint32_t length, const t_file_transfer *transfer) {
	printf("[%s] FileID: ", tag);
	print_hex_bytes(file_id, 4);
	printf("... Offset: %lu, Length: %u (Total: %lu/%lu)\n",
		   offset, length, transfer->bytes_received, transfer->file_size);
}

static void maybe_complete_and_save(t_file_transfer *transfer) {
	if (transfer->file_size > 0 && transfer->bytes_received >= transfer->file_size) {
		printf("[COMPLETE] File transfer complete for %s\n", transfer->filename);
		save_file(transfer);
	}
}

static t_pending_create *g_pending_creates = NULL;
static t_pending_read *g_pending_reads = NULL;

static void remember_pending_read(uint64_t session_id, uint64_t message_id, const uint8_t *file_id, uint64_t offset, uint32_t length) {
	if (!file_id || length == 0) {
		return;
	}

	t_pending_read *node = (t_pending_read*)calloc(1, sizeof(t_pending_read));
	if (!node) {
		return;
	}

	node->session_id = session_id;
	node->message_id = message_id;
	memcpy(node->file_id, file_id, 16);
	node->offset = offset;
	node->length = length;

	node->next = g_pending_reads;
	g_pending_reads = node;
}

static t_pending_read* take_pending_read(uint64_t session_id, uint64_t message_id) {
	t_pending_read *prev = NULL;
	t_pending_read *cur = g_pending_reads;
	while (cur) {
		if (cur->session_id == session_id && cur->message_id == message_id) {
			if (prev) prev->next = cur->next;
			else g_pending_reads = cur->next;
			cur->next = NULL;
			return cur;
		}
		prev = cur;
		cur = cur->next;
	}
	return NULL;
}

static void remember_pending_create(uint64_t session_id, uint64_t message_id, const char *filename) {
	if (!filename || filename[0] == '\0') {
		return;
	}

	t_pending_create *node = (t_pending_create*)calloc(1, sizeof(t_pending_create));
	if (!node) {
		return;
	}

	node->session_id = session_id;
	node->message_id = message_id;
	strncpy(node->filename, filename, sizeof(node->filename) - 1);

	node->next = g_pending_creates;
	g_pending_creates = node;
}

static char* take_pending_create(uint64_t session_id, uint64_t message_id) {
	t_pending_create *prev = NULL;
	t_pending_create *cur = g_pending_creates;
	while (cur) {
		if (cur->session_id == session_id && cur->message_id == message_id) {
			if (prev) prev->next = cur->next;
			else g_pending_creates = cur->next;

			char *out = strdup(cur->filename);
			free(cur);
			return out;
		}
		prev = cur;
		cur = cur->next;
	}
	return NULL;
}

// SMB2 Create 응답 처리
void handle_smb2_create(const t_smb2_header *smb_hdr, const u_char *data, int len) {
	// 요청인지 응답인지 확인 (flags의 0번 비트)
	int is_response = smb2_is_response(smb_hdr);
	
	if (!is_response) {
		if ((size_t)len < sizeof(t_smb2_create_req)) {
			return;
		}
		// Create 요청 - 파일명 추출
		t_smb2_create_req *req = (t_smb2_create_req*)data;
		uint16_t name_offset = req->name_offset;
		uint16_t name_length = req->name_length;
		
		if (name_offset > 0 && name_length > 0) {
			char *filename = extract_filename_from_create(data, len, name_offset, name_length);
			if (filename) {
				printf("[CREATE_REQ] File: %s\n", filename);
				remember_pending_create(smb_hdr->session_id, smb_hdr->message_id, filename);
				free(filename);
			}
		}
	}
	else {
		if ((size_t)len < sizeof(t_smb2_create_resp)) {
			return;
		}
		// Create 응답 - File ID 추출
		t_smb2_create_resp *resp = (t_smb2_create_resp*)data;

		char *filename = take_pending_create(smb_hdr->session_id, smb_hdr->message_id);
		if (!filename) {
			filename = strdup("Unknown");
		}

		// 이미 write/read로 인해 transfer가 생성되었을 수 있으므로, 있으면 업데이트
		t_file_transfer *transfer = find_file_transfer(resp->file_id);
		if (!transfer) {
			transfer = create_file_transfer(resp->file_id, filename);
		} else {
			if (filename && filename[0] != '\0' && strcmp(filename, "Unknown") != 0) {
				strncpy(transfer->filename, filename, sizeof(transfer->filename) - 1);
				transfer->filename[sizeof(transfer->filename) - 1] = '\0';
			}
		}
		free(filename);
		if (transfer) {
			transfer->file_size = resp->end_of_file;
			printf("[CREATE_RESP] FileID: ");
			print_hex_bytes(resp->file_id, 16);
			printf(" Size: %lu bytes\n", resp->end_of_file);
		}
	}
}

// SMB2 Write 요청 처리
void handle_smb2_write(const t_smb2_header *smb_hdr __attribute__((unused)), const u_char *data, int len) {
	if ((size_t)len < sizeof(t_smb2_write_req)) {
		return;
	}
	
	t_smb2_write_req *req = (t_smb2_write_req*)data;

	// File ID로 전송 객체 찾기 또는 생성
	t_file_transfer *transfer = find_or_create_transfer(req->file_id);
	
	if (transfer) {
		const uint8_t *write_data = NULL;
		if (smb2_extract_payload_ptr(data, len, req->data_offset, req->length, &write_data) != 0) {
			return;
		}

		if (append_file_data(transfer, write_data, req->length, req->offset) == 0) {
			log_transfer_chunk("WRITE", req->file_id, req->offset, req->length, transfer);
			maybe_complete_and_save(transfer);
		}
	}
}

// SMB2 Read 응답 처리
void handle_smb2_read(const t_smb2_header *smb_hdr, const u_char *data, int len) {
	if ((size_t)len < sizeof(t_smb2_read_resp)) {
		return;
	}
	
	// 응답인지 확인
	int is_response = smb2_is_response(smb_hdr);
	
	if (!is_response) {
		// Read 요청 - FileID/offset을 MessageId로 기억해두고, 응답에서 데이터 재조립
		if ((size_t)len < sizeof(t_smb2_read_req)) {
			return;
		}
		t_smb2_read_req *req = (t_smb2_read_req*)data;
		remember_pending_read(smb_hdr->session_id, smb_hdr->message_id, req->file_id, req->offset, req->length);
		return;
	}
	
	t_smb2_read_resp *resp = (t_smb2_read_resp*)data;
	uint16_t data_offset = resp->data_offset;
	uint32_t data_length = resp->data_length;
	
	if (data_offset == 0 || data_length == 0) {
		return;
	}
	
	t_pending_read *pending = take_pending_read(smb_hdr->session_id, smb_hdr->message_id);
	if (!pending) {
		printf("[READ_RESP] Data length: %u bytes (unmatched)\n", data_length);
		return;
	}

	const uint8_t *read_data = NULL;
	if (smb2_extract_payload_ptr(data, len, data_offset, data_length, &read_data) != 0) {
		free(pending);
		return;
	}

	t_file_transfer *transfer = find_or_create_transfer(pending->file_id);

	if (transfer) {
		if (append_file_data(transfer, read_data, data_length, pending->offset) == 0) {
			log_transfer_chunk("READ_RESP", pending->file_id, pending->offset, data_length, transfer);
			maybe_complete_and_save(transfer);
		}
	}

	free(pending);
}

// SMB2 Close 처리
void handle_smb2_close(const t_smb2_header *smb_hdr, const u_char *data, int len) {
	if (len < 24) {
		return;
	}

	// Close 응답은 무시 (요청에만 FileID가 안정적으로 존재한다고 가정)
	int is_response = smb2_is_response(smb_hdr);
	if (is_response) {
		return;
	}
	
	// Close 요청 구조: struct_size(2) + flags(2) + reserved(4) + file_id(16)
	const uint8_t *file_id = data + 8;
	
	t_file_transfer *transfer = find_file_transfer(file_id);
	if (transfer && !transfer->is_complete) {
		printf("[CLOSE] Closing file: %s\n", transfer->filename);
		
		// 파일 저장
		if (transfer->bytes_received > 0) {
			save_file(transfer);
		}
	}
}

// SMB 패킷 처리 메인 함수
void process_smb_packet(const u_char *smb_data, int smb_len, const struct pcap_pkthdr *header __attribute__((unused))) {
	// NetBIOS Session Service 헤더 확인
	if ((size_t)smb_len < sizeof(t_netbios_header)) {
		return;
	}
	
	const u_char *smb_start = smb_data + sizeof(t_netbios_header);
	int smb_payload_len = smb_len - sizeof(t_netbios_header);

	// SMB2 compound 처리 (next_command 기반)
	int offset = 0;
	while (1) {
		if (smb_payload_len - offset < (int)sizeof(t_smb2_header)) {
			return;
		}

		t_smb2_header *smb_hdr = (t_smb2_header*)(smb_start + offset);
		if (smb_hdr->protocol_id[0] != 0xFE ||
			smb_hdr->protocol_id[1] != 'S' ||
			smb_hdr->protocol_id[2] != 'M' ||
			smb_hdr->protocol_id[3] != 'B') {
			return;
		}

		uint32_t next_cmd = smb_hdr->next_command;
		int this_total_len = (next_cmd != 0) ? (int)next_cmd : (smb_payload_len - offset);
		if (this_total_len < (int)sizeof(t_smb2_header) || this_total_len > (smb_payload_len - offset)) {
			return;
		}

		uint16_t command = smb_hdr->command;
		const u_char *command_data = (const u_char*)smb_hdr + sizeof(t_smb2_header);
		int command_data_len = this_total_len - (int)sizeof(t_smb2_header);

		switch (command) {
			case SMB2_CREATE:
				handle_smb2_create(smb_hdr, command_data, command_data_len);
				break;
			case SMB2_WRITE:
				handle_smb2_write(smb_hdr, command_data, command_data_len);
				break;
			case SMB2_READ:
				handle_smb2_read(smb_hdr, command_data, command_data_len);
				break;
			case SMB2_CLOSE:
				handle_smb2_close(smb_hdr, command_data, command_data_len);
				break;
			default:
				break;
		}

		if (next_cmd == 0) {
			return;
		}
		offset += (int)next_cmd;
	}
}

// pcap 콜백 함수
void pcap_callback(u_char *args __attribute__((unused)), const struct pcap_pkthdr *header, const u_char *packet) {
	// 이더넷 헤더
	struct ether_header *eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		return;
	}
	
	// IP 헤더
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
	int ip_header_len = (ip_hdr->ip_hl) * 4;
	
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return;
	}
	
	// TCP 헤더
	struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
	int tcp_header_len = (tcp_hdr->th_off) * 4;
	
	// SMB 포트 확인 (445)
	uint16_t src_port = ntohs(tcp_hdr->th_sport);
	uint16_t dst_port = ntohs(tcp_hdr->th_dport);
	
	if (src_port != SMB_PORT && dst_port != SMB_PORT) {
		return;
	}
	
	// TCP 페이로드 (SMB 데이터)
	int total_header_len = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
	const u_char *tcp_payload = packet + total_header_len;
	int payload_len = ntohs(ip_hdr->ip_len) - ip_header_len - tcp_header_len;
	
	if (payload_len <= 0) {
		return;
	}
	
	// 큰 파일 전송의 경우 SMB 메시지가 여러 TCP 세그먼트로 분할될 수 있으므로,
	// TCP 스트림을 (간단히) 재조립한 후 NetBIOS 프레임 단위로 파싱한다.
	uint32_t seq = ntohl(tcp_hdr->th_seq);
	t_tcp_stream_buf *stream = get_stream(ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, src_port, dst_port);
	if (!stream) {
		return;
	}
	(void)header;
	tcp_stream_push_segment(stream, seq, tcp_payload, (size_t)payload_len);
}
