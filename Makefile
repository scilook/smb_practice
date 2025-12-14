CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

TARGET = smb_live_capture
SRC = smb_main.c smb_protocol.c smb_utils.c

OBJS = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

clean:
	rm -f *.o

fclean: clean
	rm -f $(TARGET)
	rm -f copied_* *.dat

re: fclean all

install-deps:
	sudo apt-get update
	sudo apt-get install -y libpcap-dev

install-deps-rpm:
	sudo yum install -y libpcap-devel || sudo dnf install -y libpcap-devel

run: $(TARGET)
	@echo "Starting SMB live capture (requires root/sudo)"
	sudo ./$(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: re

test-smb:
	@echo "Testing SMB connection..."
	@echo "Make sure you have an SMB share mounted or accessible"
	@echo "Example: sudo mount -t cifs //server/share /mnt/point -o username=user"

help:
	@echo "SMB v3 Live File Capture Tool - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build the SMB capture program (default)"
	@echo "  clean            - Remove object files"
	@echo "  fclean           - Remove all generated files including captured files"
	@echo "  re               - Rebuild everything from scratch"
	@echo "  install-deps     - Install libpcap (Debian/Ubuntu)"
	@echo "  install-deps-rpm - Install libpcap (RHEL/CentOS/Fedora)"
	@echo "  run              - Build and run with sudo"
	@echo "  debug            - Build with debug symbols"
	@echo "  test-smb         - Show SMB testing instructions"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  sudo ./$(TARGET) [interface]"
	@echo ""
	@echo "Examples:"
	@echo "  sudo ./$(TARGET)           - Use default interface"
	@echo "  sudo ./$(TARGET) eth0      - Use eth0 interface"
	@echo ""
	@echo "Captured files will be saved as:"
	@echo "  - copy_<original_filename>  (if filename is detected)"
	@echo "  - <unix_timestamp>.dat      (if filename is unknown)"

.PHONY: all clean fclean re install-deps install-deps-rpm run debug test-smb help
