#include "smb_capture.h"

// 전역 변수
t_file_transfer *g_transfers = NULL;
pcap_t *g_handle = NULL;
char *g_output_dir;


// 파일 전송 객체 찾기
t_file_transfer* find_file_transfer(const uint8_t *file_id) {
	t_file_transfer *current = g_transfers;
	
	while (current != NULL) {
		if (memcmp(current->file_id, file_id, 16) == 0)
		return current;
		current = current->next;
	}
	
	return NULL;
}

// 새 파일 전송 객체 생성
t_file_transfer* create_file_transfer(const uint8_t *file_id, const char *filename) {
	t_file_transfer *transfer = (t_file_transfer*)calloc(1, sizeof(t_file_transfer));
	if (!transfer) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}
	
	memcpy(transfer->file_id, file_id, 16);
	if (filename) {
		strncpy(transfer->filename, filename, sizeof(transfer->filename) - 1);
	} else {
		snprintf(transfer->filename, sizeof(transfer->filename), "file_%ld", time(NULL));
	}
	
	transfer->data_capacity = 1024 * 1024; // 초기 1MB
	transfer->file_data = (uint8_t*)malloc(transfer->data_capacity);
	if (!transfer->file_data) {
		free(transfer);
		return NULL;
	}
	
	transfer->start_time = time(NULL);
	transfer->next = g_transfers;
	g_transfers = transfer;
	
	printf("[NEW FILE] Tracking: %s\n", transfer->filename);
	
	return transfer;
}

// 파일 데이터 추가
int append_file_data(t_file_transfer *transfer, const uint8_t *data, uint32_t len, uint64_t offset) {
	if (!transfer || !data || len == 0) {
		return -1;
	}
	
	uint64_t required_size = offset + len;
	
	// 버퍼 확장 필요한 경우
	if (required_size > transfer->data_capacity) {
		uint32_t new_capacity = transfer->data_capacity;
		while (new_capacity < required_size) {
			new_capacity *= 2;
		}
		
		uint8_t *new_data = (uint8_t*)realloc(transfer->file_data, new_capacity);
		if (!new_data) {
			fprintf(stderr, "Failed to expand buffer for %s\n", transfer->filename);
			return -1;
		}
		
		transfer->file_data = new_data;
		transfer->data_capacity = new_capacity;
	}
	
	// 데이터 복사
	memcpy(transfer->file_data + offset, data, len);
	transfer->bytes_received += len;
	
	// 파일 크기 업데이트
	if (offset + len > transfer->file_size) {
		transfer->file_size = offset + len;
	}
	
	return 0;
}

// 출력 경로 설정 및 준비
int set_output_directory(const char *path) {
	if (!path || strlen(path) == 0) {
		fprintf(stderr, "[ERROR] Invalid output directory\n");
		return -1;
	}

	struct stat st;
	if (stat(path, &st) != 0) {
		if (mkdir(path, 0755) != 0) {
			fprintf(stderr, "[ERROR] Failed to create directory %s (%s)\n", path, strerror(errno));
			return -1;
		}
	}
	else if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "[ERROR] %s is not a directory\n", path);
		return -1;
	}

	char *new_output_dir = strdup(path);
	if (!new_output_dir) {
		fprintf(stderr, "[ERROR] Failed to set output directory (%s)\n", strerror(errno));
		return -1;
	}

	g_output_dir = new_output_dir;

	return 0;
}

// 파일 저장
void save_file(t_file_transfer *transfer) {
	if (!transfer || !transfer->file_data || transfer->file_size == 0) {
		return;
	}

	char output_filename[1024];
	
	// 파일명에서 경로 구분자 제거
	char *basename = strrchr(transfer->filename, '\\');
	if (!basename) {
		basename = strrchr(transfer->filename, '/');
	}
	if (basename) {
		basename++;
	}
	else {
		basename = transfer->filename;
	}
	
	// 재조합 파일 이름 설정
	if (strlen(basename) > 0 && strcmp(basename, "Unknown") != 0) {
		snprintf(output_filename, sizeof(output_filename), "%s/copied_%s", g_output_dir, basename);
	}
	else {
		snprintf(output_filename, sizeof(output_filename), "%s/%ld.dat", g_output_dir, (long)transfer->start_time);
	}
	
	FILE *fp = fopen(output_filename, "wb");
	if (!fp) {
		fprintf(stderr, "[ERROR] Cannot create file: %s (%s)\n", output_filename, strerror(errno));
		return;
	}
	
	size_t written = fwrite(transfer->file_data, 1, transfer->file_size, fp);
	fclose(fp);
	
	if (written == transfer->file_size) {
		printf("[SAVED] File: %s (Size: %lu bytes)\n", output_filename, transfer->file_size);
		transfer->is_complete = 1;
	}
	else
		fprintf(stderr, "[ERROR] Incomplete write for %s\n", output_filename);
}

// 메모리 정리
void cleanup_transfers() {
	t_file_transfer *current = g_transfers;
	
	while (current != NULL) {
		t_file_transfer *next = current->next;
		
		// 완료되지 않은 파일도 저장 시도
		if (!current->is_complete && current->bytes_received > 0) {
			printf("[CLEANUP] Saving incomplete file: %s\n", current->filename);
			save_file(current);
		}
		
		if (current->file_data) {
			free(current->file_data);
		}
		free(current);
		current = next;
	}
	
	g_transfers = NULL;

	free(g_output_dir);
	g_output_dir = NULL;
}

// UTF-16LE를 UTF-8로 변환 (간단한 ASCII 범위만)
char* utf16le_to_utf8(const uint8_t *utf16_data, int byte_len) {
	if (!utf16_data || byte_len <= 0) {
		return NULL;
	}
	
	int char_count = byte_len / 2;
	char *result = (char*)malloc(char_count + 1);
	if (!result) {
		return NULL;
	}
	
	for (int i = 0; i < char_count; i++) {
		uint16_t c = utf16_data[i * 2] | (utf16_data[i * 2 + 1] << 8);
		if (c == 0) {
			result[i] = '\0';
			break;
		}
		// ASCII 범위만 처리, 나머지는 '?'로 대체
		result[i] = (c < 128) ? (char)c : '?';
	}
	result[char_count] = '\0';
	
	return result;
}

// SMB2 Create 요청에서 파일명 추출
char* extract_filename_from_create(const u_char *data, int len, uint16_t name_offset, uint16_t name_length) {
	if (name_offset == 0 || name_length == 0) {
		return strdup("Unknown");
	}
	
	// SMB2 헤더 기준으로 오프셋 계산
	int actual_offset = name_offset - SMB2_HEADER_SIZE;
	
	if (actual_offset < 0 || actual_offset + name_length > len) {
		return strdup("Unknown");
	}
	
	char *filename = utf16le_to_utf8(data + actual_offset, name_length);
	if (!filename)
		return strdup("Unknown");
	return filename;
}

// 시그널 핸들러
void signal_handler(int signum) {
	printf("\n[SIGNAL] Caught signal %d, cleaning up...\n", signum);
	if (g_handle) pcap_breakloop(g_handle);
}
