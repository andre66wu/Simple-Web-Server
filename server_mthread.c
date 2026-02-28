#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>

int is_daemon = 0;
char web_root[128] = "/home/andre/myweb";

int sig_pending = 0;
int child_num = 0;

#define MAX_CHILD 256
int port = 80;

void str2lower(char *str) 
{
    if (str == NULL) return;
    for (char *p = str; *p; p++) {
        *p = tolower((unsigned char)*p);
    }
}

int dir_exist(const char* path) 
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) 
        return 1;
    else
        return -1;
}

void log_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (is_daemon) {
        vsyslog(LOG_INFO, fmt, ap);
    } else {
        vfprintf(stdout, fmt, ap);
        fflush(stdout);          // 防止 fork/重定向时缓冲问题
    }

    va_end(ap);
}

void wait_child() 
{
    pid_t pid = 0;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        --child_num;
        log_msg("child %d exit, num %d\n", pid, child_num);
    }
    if (pid < 0)
	    log_msg("waitpid: %s", strerror(errno));
}

// 信号处理函数：异步回收子进程资源
void sigchld_handler(int sig) 
{
    sig_pending = 1;
}

void sigterm_handler(int sig) 
{
    log_msg("Received SIGTERM. Server %d is shutting down\n", getpid());
    exit(0);
}

int recv_line(int sock_fd, char *buffer, int length, int timeout)
{
        char *ptr;
        int n, left = length;
        fd_set fds;
        int i, res, max_loops = 4;
        struct timeval wait;

        wait.tv_sec = timeout;
        wait.tv_usec = 0;

        ptr = buffer;
        i = 0;
        while (i++ < max_loops && left != 0) {
                FD_ZERO(&fds);
                FD_SET(sock_fd, &fds);

                res = select(sock_fd + 1, &fds, NULL, NULL, &wait);
                if (res < 0) {
                        if (errno == EINTR) continue;
			            perror("recv_line select");
                        return -1;
                } else if (res == 0) {
                        return (length - left);
                }

                n = recv(sock_fd, ptr, left, 0);
                if (n > 0) {
                        left -= n;
                        ptr += n;
                        if (strchr(buffer, '\n')) break;
                } else if (n == 0) {
                        return (length - left);
                } else {
			            perror("recv");
                        return -1;
                }
        }
        return (length - left);
}

int send_all(int sock_fd, const char *buffer, int length, int timeout) 
{
    int left = length;      // 剩余需要发送的字节数
    const char *ptr = buffer; // 当前发送的位置指针
    struct timeval wait;
    fd_set fds;
    int res;

    while (left > 0) {
        // 1. 使用 select 等待套接字变为“可写”
        FD_ZERO(&fds);
        FD_SET(sock_fd, &fds);
        wait.tv_sec = timeout;
        wait.tv_usec = 0;

        res = select(sock_fd + 1, NULL, &fds, NULL, &wait);
        if (res < 0) {
            if (errno == EINTR) continue; // 被信号中断则重试
            perror("send_all select");
            return -1;
        } else if (res == 0) {
            return (length - left); // 超时，返回已发送的字节数
        }

        // 2. 只有当 select 告诉我们“可写”时才调用 send
        int n = send(sock_fd, ptr, left, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) n = 0; // 再次处理中断
            else return -1; // 真正的错误（如对端关闭连接引发 EPIPE）
        }

        left -= n; // 更新剩余字节数
        ptr += n;  // 指针向后移动
    }
    return length; // 全部发送成功
}

// 子进程业务逻辑：处理 HTTP 请求
void handle_http_request(int conn_fd) 
{
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    int len = recv_line(conn_fd, buf, sizeof(buf), 60);
    
    char method[16], url[256], protocol[16];
    bzero(method, sizeof(method));
    bzero(url, sizeof(url));
    bzero(protocol, sizeof(protocol));
    if (sscanf(buf, "%15s %255s %15s", method, url, protocol) != 3) {
        log_msg("Bad Request: %d\n", len);
        return;
    }

    // 调试语句
    log_msg("[%s] Request Path: %s\n", method, url);

    if (strcmp(method, "GET") == 0) {
        char real_path[512];
	    str2lower(url);

        len = snprintf(real_path, sizeof(real_path), "%s%s", web_root, url);
        log_msg("Child process %d is looking for: [%s]\n", getpid(), real_path);
        if (real_path[strlen(real_path) - 1] == '/' &&
	    sizeof(real_path) - len > 11)
		strcat(real_path, "index.html");

        FILE *fp;
        fp = fopen(real_path, "rb");
        if (fp) {
            // 发送 200 OK
            send(conn_fd, "HTTP/1.1 200 OK\r\n\r\n", 19, 0);
            char file_buf[4096];
            size_t n;
            while ((n = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
                if (send_all(conn_fd, file_buf,n, 30) < 0){ //30秒超时
                    perror("send_all failed");
                    break;
                }
            }
            fclose(fp);
        } else {
            // 发送 404
            char *not_found = "HTTP/1.1 404 NOT FOUND\r\n\r\nFile Not Found";
            send(conn_fd, not_found, strlen(not_found), 0);
        }
    }
}

/*
 * -d, --daemon: run as daemon
 * -r, --root: root dir of web se3rver
 */
int main(int argc, char **argv)
{
    int listen_fd;
    struct sockaddr_in serv_addr, cli_addr;
    
    struct option opts[] = {
	{"daemon", 0, 0, 'd'},
	{"root", 1, 0, 'r'},
	{"port", 1, 0, 'p'},
	{0, 0, 0, 0}
    };
    int opt_c = 0;

    while ((opt_c = getopt_long(argc, argv, "dr:p:", opts, NULL)) >= 0) {
        switch (opt_c) { 
	    case 'd':
	        is_daemon = 1;
	        break;
	    case 'r':
	        snprintf(web_root, sizeof(web_root), "%s", optarg);
	        if (dir_exist(web_root) != 1) {
		        printf("web_root does not exist\n)");
		        exit(-1);
	        }
	        break;
	    case 'p':
	        port = atoi(optarg);
	        break;
    	default:
	        //usage();
	        break;
	    }
    }

    // 1. 初始化 Socket
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    perror("socket");
        exit(-1);
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); // 防止端口占用
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
	    perror("bind");
        exit(-1);
    }

    listen(listen_fd, 10);

    // 2. 注册信号处理，防止僵尸进程
    signal(SIGCHLD, sigchld_handler);
    signal(SIGTERM, sigterm_handler);

    printf("Web Server started on port %d, root %s...\n", port, web_root);

    if (is_daemon) daemon(0, 0);

    fd_set read_fds;
    int res;

    while (1) {

        if (sig_pending) {
             wait_child();
             sig_pending = 0;
        }

        if (child_num >= MAX_CHILD) {
            log_msg("serv throttled at child num %d\n", child_num);
            usleep(1000);
            continue;
        }

        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);

        // 3. 使用 select 监视状态
        if ((res = select(listen_fd + 1, &read_fds, NULL, NULL, NULL)) < 0) {
            if (errno == EINTR) continue; // 忽略信号中断
	        perror("main select");
            exit(-1);
        }

        if (res > 0 && FD_ISSET(listen_fd, &read_fds)) {
            int namelen = sizeof(cli_addr);
            int conn_fd = accept(listen_fd, (struct sockaddr *) &cli_addr, (socklen_t *) &namelen);
            if (conn_fd < 0) {
                perror("accept");
                exit(-1);
            }
	        log_msg("accept from %s : %u\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

            // 4. fork 子进程处理
            pid_t pid;

            if ((pid = fork()) == 0) {
                close(listen_fd);
                handle_http_request(conn_fd);
                close(conn_fd);
                //printf("child %d finished\n", getpid());
                exit(0); // 子进程必须退出
            } else if (pid > 0)  {
                ++child_num;
                log_msg("child %d started, num %d\n", pid,
                       child_num);
                close(conn_fd); // 父进程关闭引用
            } else {
		        perror("fork");
		        exit(-1);
            }
        }
    }
    close(listen_fd);
    return 0;
}
