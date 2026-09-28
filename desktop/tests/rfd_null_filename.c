#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test-only boundary fault. GTK's own internal calls and every other process
 * retain the original function. The armed file identifies one disposable app
 * process and its exact XDG directory, and unlink consumes it only once. */
char *gtk_file_chooser_get_filename(void *chooser) {
    typedef char *(*GetFilename)(void *);
    typedef void (*FreeString)(void *);
    GetFilename original = (GetFilename)dlsym(RTLD_NEXT, "gtk_file_chooser_get_filename");
    if (!original) return NULL;
    char *filename = original(chooser);
    const char *app = getenv("_THRONIUM_RFD_APP");
    const char *root = getenv("_THRONIUM_RFD_ROOT");
    const char *nonce = getenv("_THRONIUM_RFD_NONCE");
    const char *xdg = getenv("XDG_DATA_HOME");
    if (!app || !root || !nonce || !xdg || app[0] != '/' || root[0] != '/') return filename;
    if (!strstr(xdg, "/thronium-native-test-") || strlen(xdg) < 6 ||
        strcmp(xdg + strlen(xdg) - 5, "/data") || strstr(xdg, "/../") || strchr(xdg, '\n')) return filename;
    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length < 0) return filename;
    executable[length] = 0;
    if (strcmp(executable, app)) return filename;
    Dl_info caller;
    if (!dladdr(__builtin_return_address(0), &caller) || !caller.dli_fname || strcmp(caller.dli_fname, app)) return filename;
    struct stat directory;
    if (lstat(root, &directory) || !S_ISDIR(directory.st_mode) || directory.st_uid != getuid() || (directory.st_mode & 0077)) return filename;
    char flag[PATH_MAX], audit[PATH_MAX], expected[8192], contents[8192];
    if (snprintf(flag, sizeof(flag), "%s/once.flag", root) >= (int)sizeof(flag) ||
        snprintf(audit, sizeof(audit), "%s/audit.jsonl", root) >= (int)sizeof(audit)) return filename;
    int fd = open(flag, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return filename;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != getuid() || info.st_nlink != 1 ||
        (info.st_mode & 0077) || info.st_size <= 0 || info.st_size >= (off_t)sizeof(contents)) {
        close(fd); return filename;
    }
    ssize_t bytes = read(fd, contents, sizeof(contents) - 1);
    close(fd);
    if (bytes != info.st_size) return filename;
    contents[bytes] = 0;
    int prefix = snprintf(expected, sizeof(expected), "%ld\n%s\n%s\n", (long)getpid(), xdg, nonce);
    if (prefix < 0 || prefix >= (int)sizeof(expected) || strncmp(contents, expected, (size_t)prefix)) return filename;
    const char *mode = contents + prefix;
    if (strcmp(mode, "open\n") && strcmp(mode, "save\n")) return filename;
    FreeString release = (FreeString)dlsym(RTLD_NEXT, "g_free");
    if (!release || unlink(flag)) return filename;
    int was_null = filename == NULL;
    if (filename) release(filename);
    fd = open(audit, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        char row[256];
        int size = snprintf(row, sizeof(row), "{\"pid\":%ld,\"mode\":\"%s\",\"callerIsApp\":true,\"originalWasNull\":%s,\"originalFreed\":%s,\"returnedNull\":true}\n",
            (long)getpid(), mode[0] == 'o' ? "open" : "save", was_null ? "true" : "false", was_null ? "false" : "true");
        if (size > 0 && size < (int)sizeof(row)) (void)write(fd, row, (size_t)size);
        close(fd);
    }
    return NULL;
}
