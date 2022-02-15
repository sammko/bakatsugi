#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#define SZ_COOKIE 16

extern long my_syscall(long number, ...);
extern void *my_dlopen(const char *filename, int flags);

void *my_memset(void *s, int c, size_t sz) {
  uint8_t *p = (uint8_t *)s;
  uint8_t x = c & 0xff;

  while (sz--)
    *p++ = x;
  return s;
}

void *my_memcpy(void *dest, void *src, size_t n) {
  uint8_t *ps = (uint8_t *)src;
  uint8_t *pd = (uint8_t *)dest;

  while (n--)
    *pd++ = *ps++;

  return dest;
}

int connect_socket(char *cookie) {
  struct sockaddr_un addr;
  my_memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  my_memcpy(&addr.sun_path[1], cookie, SZ_COOKIE);

  int sock = my_syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
  if (sock == -1) {
    return -1;
  }
  int r = my_syscall(SYS_connect, sock, (const struct sockaddr *)&addr,
                     offsetof(struct sockaddr_un, sun_path) + SZ_COOKIE + 1);
  if (r < 0) {
    return -1;
  }
  return sock;
}

int recv_fd(int sock) {
  char c;
  struct iovec iov[1] = {{
      .iov_base = &c,
      .iov_len = sizeof(c),
  }};

  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr cmsghdr;
  } u;
  my_memset(&u.buf, 0, sizeof(u.buf));

  u.cmsghdr.cmsg_len = CMSG_LEN(sizeof(int));
  u.cmsghdr.cmsg_level = SOL_SOCKET;
  u.cmsghdr.cmsg_type = SCM_RIGHTS;

  struct msghdr msg = {
      .msg_control = u.buf,
      .msg_controllen = sizeof(u.buf),
      .msg_flags = 0,
      .msg_iov = iov,
      .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
      .msg_name = NULL,
      .msg_namelen = 0,
  };

  ssize_t nbytes = my_syscall(SYS_recvmsg, sock, &msg, 0);
  if (nbytes == -1) {
    return -1;
  }

  int *p = (int *)CMSG_DATA(&u.cmsghdr);
  my_syscall(SYS_close, sock);
  return *p;
}

void payload_main(char *cookie) {
  int sock = connect_socket(cookie);
  if (sock == -1) {
    return;
  }
  int fd = recv_fd(sock);
  if (fd == -1) {
    return;
  }
  int fd2 = fd;

  char path[] = "/proc/self/fd/........";
  char fds[8];
  char *fdp = fds;
  for (; fd2; fd2 /= 10) {
    *fdp++ = (fd2 % 10) + '0';
  }
  int i;
  for (i = 0; i < fdp - fds; i++) {
    path[i + 14] = *(fdp - i - 1);
  }
  path[i + 14] = '\0';

  my_dlopen(path, RTLD_LAZY);
  my_syscall(SYS_close, fd);
}
