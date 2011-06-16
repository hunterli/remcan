/*
 * remcan
 * Copyright (C) 2010 www.yuan-ying.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <libgen.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#include "can.h"
#include "raw.h"

#define VERSION "1.0"

static struct can_filter *filter = NULL;
static int filter_count = 0;

int add_filter(u_int32_t id, u_int32_t mask)
{
	filter = realloc(filter, sizeof(struct can_filter) * (filter_count + 1));
	if(!filter)
		return -1;

	filter[filter_count].can_id = id;
	filter[filter_count].can_mask = mask;
	filter_count++;

	return 0;
}

static int is_daemon = 0, debug = 0, is_running = 1;
static int max_connections = 1;
static int port = 24000;
static char *can_name = NULL;

static int server_fd = -1, can_fd = -1;
static int *client_fds = NULL;
static int curr_conn_num = 0;

static void print_usage(char *prg)
{
    fprintf(stderr, "Usage: %s <can-interface> [Options]\n"
                    "Options:\n"
                    " -p, --port=PORT\t"	"server listenning port (default: %d)\n"
                    " -m, --max-connections=NUM\t"	"max clients (default: %d)\n"
                    " -d, --daemon\t"	"run in daemonsized\n"
                    " -f, --filter=id:mask[:id:mask]...\t"	"CAN filter string id=HEX_CAN_ID mask=HEX_CAN_MASK\n"
                    " -h, --help\t"	"this help\n"
                    " -V, --version\t"	"version: %s\n"
                    " --debug\t"	"debug mode\n",
                    prg, port, max_connections, VERSION);
}

static void print_params(void)
{
    fprintf(stderr, "is_daemon=%d, max_connections=%d, port=%d, can_name=%s, debug=%d\n", is_daemon, max_connections, port, can_name, debug);
    if (filter_count) {
        int i;
        fprintf(stderr, "CAN filters: ");
        for (i = 0; i < filter_count; ++i) {
            fprintf(stderr, " id=0x%08x mask=0x%08x,", (filter+i)->can_id, (filter+i)->can_mask);
        }
        fprintf(stderr, "\n");
    }
}

extern int optind, opterr, optopt;

enum
{
	VERSION_OPTION = CHAR_MAX + 1,
	DEBUG,
};

static void parse_cmd(int argc, char **argv)
{
    int opt;
    char *ptr;
    unsigned int id, mask;
	struct option		long_options[] = {
		{ "port", 1, 0, 'p' },
		{ "max-connections", 1, 0, 'm' },
		{ "daemon", 0, 0, 'd' },
		{ "filter", 1, 0, 'f' },
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'V'},
		{ "debug", 0, 0, DEBUG},
		{ 0, 0, 0, 0},
	};

	while ((opt = getopt_long(argc, argv, "p:m:df:hV", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;

		case 'm':
			max_connections = atoi(optarg);
			break;

		case 'd':
			is_daemon = 1;
			break;

		case 'f':
			ptr = optarg;
			while(1) {
				id = strtoul(ptr, NULL, 0);
				ptr = strchr(ptr, ':');
				if(!ptr) {
					fprintf(stderr, "filter must be applied in the form id:mask[:id:mask]...\n");
					exit(1);
				}
				ptr++;
				mask = strtoul(ptr, NULL, 0);
				ptr = strchr(ptr, ':');
				add_filter(id,mask);
				if(!ptr)
					break;
				ptr++;
			}
			break;

		case 'h':
			print_usage(basename(argv[0]));
			exit(0);

		case 'V':
			printf("remcan %s\n",VERSION);
			exit(0);

        case DEBUG:
            debug = 1;
            break;

		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			break;
		}
	}

	if (optind == argc) {
		print_usage(basename(argv[0]));
		exit (EXIT_SUCCESS);
	}
    if(debug)print_params();

	can_name = argv[optind];
	client_fds = malloc (max_connections * sizeof(int));
}

static void close_all_fds(void)
{
	int i;

	if ( server_fd != -1 ) close(server_fd);
	if ( can_fd != -1 ) close(can_fd);
	for (i=0 ; i<curr_conn_num ; i++) close(client_fds[i]);
}

static void sig_handler(int sig)
{
    close_all_fds();
    if(debug) fprintf(stderr,"Terminating on signal %d\n",sig);
	exit(0);
}

static void setup_signal(void)
{
    signal(SIGINT,sig_handler);
    signal(SIGHUP,sig_handler);
    signal(SIGTERM,sig_handler);
}

static void tcp_listening(void)
{
    struct sockaddr_in addr;
    int reuse_sock = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( server_fd == -1 ) {
    	fprintf(stderr, "Can't open socket: %d\n", errno);
    	exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_sock, sizeof(reuse_sock)) < 0) {
    	fprintf(stderr, "Couldn't bind port %d, aborting: %d\n", port, errno );
    	exit(1);
    }

    /* Set up to listen on the given port */
    if( bind( server_fd, (struct sockaddr*)(&addr), sizeof(struct sockaddr_in)) < 0 ) {
    	fprintf(stderr, "Couldn't bind port %d, aborting: %d\n", port, errno );
    	exit(1);
    }

    /* Tell the system we want to listen on this socket */
    if ( -1 == (listen(server_fd, 4))) {
    	fprintf(stderr, "Socket listen failed: %d\n", errno);
    	exit(1);
    }
    if ( debug )
    	fprintf(stderr, "Bound port: %d\n", port);
}

static void can_listening(void)
{
    struct sockaddr_can addr;
    struct ifreq ifr;

    can_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if ( can_fd == -1 ) {
    	perror("create socket PF_CAN SOCK_RAW CAN_RAW");
    	exit(1);
    }
    addr.can_family = AF_CAN;
    strcpy(ifr.ifr_name, can_name);
    if (ioctl(can_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(can_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("bind");
        exit(1);
    }
	if(filter) {
		if(setsockopt(can_fd, SOL_CAN_RAW, CAN_RAW_FILTER, filter, filter_count * sizeof(struct can_filter)) != 0) {
			perror("setsockopt");
			exit(1);
		}
	}
    if ( debug )
    	fprintf(stderr, "Bound CAN: %s\n", can_name);
}

static void listening(void)
{
    tcp_listening();
    can_listening();
    if ( debug )
    	fprintf(stderr, "Done listen\n");

	if (is_daemon) daemon(1, 0);
}

static int prepare_fd_set(fd_set *read_set)
{
    int i, max_fd = -1;

    FD_ZERO(read_set);
	if ( server_fd != -1 ) {
		FD_SET(server_fd, read_set);
		if ( server_fd >= max_fd )
			max_fd = server_fd + 1;
	}

	if ( can_fd != -1 ) {
		FD_SET(can_fd, read_set);
		if ( can_fd >= max_fd )
			max_fd = can_fd + 1;
	}

	for (i=0 ; i<curr_conn_num ; i++) {
		FD_SET(client_fds[i],read_set);
		if ( client_fds[i] >= max_fd )
			max_fd = client_fds[i] + 1;
	}

	return max_fd;
}

static void do_accept(fd_set *read_set)
{
    if (FD_ISSET(server_fd,read_set) ) {
    	int fd, ip, addr_len;
    	struct sockaddr_in addr;

		addr_len = sizeof(addr);
		fd = accept(server_fd, (struct sockaddr*)(&addr), &addr_len);
		if ( fd == -1 ) {
			perror("do_accept failed");
		} else if (curr_conn_num < max_connections) {
			unsigned long ip;
			client_fds[curr_conn_num++] = fd;
			ip = ntohl(addr.sin_addr.s_addr);
			if(debug)fprintf(stderr, "Connection from %d.%d.%d.%d\n",
				(int)(ip>>24)&0xff,
				(int)(ip>>16)&0xff,
				(int)(ip>>8)&0xff,
				(int)(ip>>0)&0xff);
		} else {
			close(fd);
		}
	}
}

static int can_frame_to_str(struct can_frame *frame, char *buf, size_t buf_len)
{
    int i, n;

    if (frame->can_id & CAN_EFF_FLAG)
    	n = snprintf(buf, buf_len, "<0x%08x> ", frame->can_id & CAN_EFF_MASK);
    else
    	n = snprintf(buf, buf_len, "<0x%03x> ", frame->can_id & CAN_SFF_MASK);

    n += snprintf(buf + n, buf_len - n, "[%d] ", frame->can_dlc);
    for (i = 0; i < frame->can_dlc; i++) {
    	n += snprintf(buf + n, buf_len - n, "%02x ", frame->data[i]);
    }
    if (frame->can_id & CAN_RTR_FLAG)
    	n += snprintf(buf + n, buf_len - n, "remote request");
	n += snprintf(buf + n, buf_len - n, "\n");
	return n;
}

#if 0
static char *HEX = "0123456789ABCDEF";
static int buf_to_hex_str(char *dest_buf, size_t dest_buf_len, char *src_buf, size_t src_buf_len)
{
    int i, j;
    unsigned char c;

    for(i = 0, j = 0; i < dest_buf_len && j < src_buf_len; i += 2, ++j) {
        c = src_buf[j];
        dest_buf[i] = HEX[(0xF0 & c) >> 4];
        dest_buf[i+1] = HEX[0x0F & c];
    }
    dest_buf[i] = 0;
    return i;
}
#endif //0

static void write_to_clients(fd_set *read_set, void *buf, size_t buf_len)
{
    int i, n;

	for (i=0 ; i < curr_conn_num ; i++) {
	    n = write(client_fds[i], buf, buf_len);
		if (debug) fprintf(stderr, "write to client[%d]: %d bytes\n", client_fds[i], n);
		if ( n <= 0 ) {
			register int j;
			if(debug)fprintf(stderr, "Connection[%d] error or closed", client_fds[i]);
			close(client_fds[i]);
			FD_CLR(client_fds[i], read_set);
			curr_conn_num--;
			for (j=i ; j<curr_conn_num; ++j)
				client_fds[j] = client_fds[j+1];
		}
	}
}

static void do_read_can(fd_set *read_set)
{
    if (FD_ISSET(can_fd, read_set) ) {
        int n, addr_len;
        struct sockaddr_can addr;
        struct can_frame frame;

        addr_len = sizeof(addr);
        n = read(can_fd, &frame, sizeof(frame));
        if (n <= 0) {
            perror("read can");
            close(can_fd);
            can_listening(); //reopen CAN
        } else {
            char buf[512] = {0};
            if(debug){
                n = can_frame_to_str(&frame, buf, sizeof(buf)-1);
                write_to_clients(read_set, buf, n);
                fprintf(stderr, ">>>>>>>>CAN PACKET: %s", buf);
            } else {
                write_to_clients(read_set, &frame, n);
            }
        }
    }
}

static void do_read_clients(fd_set *read_set)
{
    int i, n;
    char *buf[512];

	for (i=0 ; i<curr_conn_num ; i++)
		if (FD_ISSET(client_fds[i], read_set) ) {
			n = read(client_fds[i], buf, sizeof(buf));
			if (debug) fprintf(stderr, "Remote: %d bytes\n", n);
			if ( n <= 0 ) {
				register int j;
				if(debug)fprintf(stderr, "Connection[%d] error or closed", client_fds[i]);
				close(client_fds[i]);
				FD_CLR(client_fds[i], read_set);
				curr_conn_num--;
				for (j=i ; j<curr_conn_num; ++j)
					client_fds[j] = client_fds[j+1];
			} else if ( can_fd != -1 )
				/* Write the data to the device */
				write(can_fd, buf, n);
	}
}

static void serve_forever(void)
{
    fd_set read_set;
	int i, max_fd = -1;

    while(is_running) {
        max_fd = prepare_fd_set(&read_set);
		if ( select(max_fd,&read_set,NULL,NULL,NULL) == -1 )
			break;
		do_accept(&read_set);
        do_read_can(&read_set);
        do_read_clients(&read_set);
    }
}

int main(int argc, char *argv[])
{
    parse_cmd(argc, argv);
    setup_signal();
    listening();
    serve_forever();
    close_all_fds();
}
