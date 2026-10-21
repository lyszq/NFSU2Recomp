#import "NFSU2GameSession.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void copy_text(char *destination, size_t capacity, const char *source) {
    if (!destination || capacity == 0) return;
    snprintf(destination, capacity, "%s", source ? source : "");
}

#if defined(NFS_FULL_RUNTIME)

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <pthread.h>
#import <pthread/qos.h>
#import <setjmp.h>
#import <fcntl.h>
#import <unistd.h>
#include <sys/stat.h>

#include "cpu.h"
#include "decls.h"
#include "guest_bootstrap.h"
#include "metal.h"
#include "NFSU2InputBridge.h"

extern void dispatch_init(void);
extern void win32_init(void);
extern void overrides_install(void);
extern void guest_lock(CPU *cpu);
extern void guest_unlock(void);
extern void fileio_set_root(const char *executable_path);
extern void fileio_set_write_root(const char *directory_path);

extern jmp_buf g_exit_jmp;
extern int g_exit_code;
extern int g_exit_armed;
extern uint32_t g_image_base;
extern uint32_t g_image_size;
extern uint32_t g_image_entry;
extern CPU *g_cur_cpu;

enum { NFS_GAME_GUEST_STACK_BYTES = 16 * 1024 * 1024 };
static const size_t kExpectedExecutableSize = 4788224u;
static const char kExpectedExecutableSHA256[] =
    "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297";

static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_session_resume = PTHREAD_COND_INITIALIZER;
static int g_session_state = NFS_GAME_SESSION_IDLE;
static int g_session_started = 0;
static int g_session_active = 1;
static int g_pause_requested = 0;
static int g_guest_thread_created = 0;
static char g_session_status[512] = "Full runtime session has not started.";
static CPU g_primary_cpu;

static NSString *runtime_log_path(void) {
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject;
    return directory ? [directory stringByAppendingPathComponent:@"NFSU2Runtime.log"] : nil;
}

static void copy_plist_field(NSString *key, char *destination, size_t capacity) {
    if (!destination || capacity == 0) return;
    destination[0] = '\0';
    id value = [[NSBundle mainBundle] objectForInfoDictionaryKey:key];
    if (![value isKindOfClass:[NSString class]]) {
        snprintf(destination, capacity, "unset");
        return;
    }

    const char *utf8 = [(NSString *)value UTF8String];
    if (!utf8) {
        snprintf(destination, capacity, "unset");
        return;
    }
    size_t out = 0;
    for (size_t i = 0; utf8[i] && out + 1 < capacity && out < 128; ++i) {
        unsigned char c = (unsigned char)utf8[i];
        destination[out++] = ((c >= 'a' && c <= 'z') ||
                              (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') ||
                              c == '.' || c == '_' || c == '-') ? (char)c : '_';
    }
    destination[out] = '\0';
    if (out == 0) snprintf(destination, capacity, "unset");
}

static void redirect_runtime_stderr(void) {
    @autoreleasepool {
        NSString *path = runtime_log_path();
        NSError *directory_error = nil;
        NSString *directory = [path stringByDeletingLastPathComponent];
        if (!path || ![[NSFileManager defaultManager]
                createDirectoryAtPath:directory
          withIntermediateDirectories:YES
                           attributes:nil
                                error:&directory_error]) {
            /* Keep the current stderr descriptor intact if Documents cannot be prepared. */
            dprintf(STDERR_FILENO, "NFSU2 log unavailable; stderr redirection skipped.\n");
            return;
        }

        int log_fd = open(path.fileSystemRepresentation,
                          O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
        if (log_fd < 0) {
            dprintf(STDERR_FILENO,
                    "NFSU2 log unavailable (open error %d); stderr redirection skipped.\n",
                    errno);
            return;
        }
        if (dup2(log_fd, STDERR_FILENO) < 0) {
            int saved_errno = errno;
            if (log_fd != STDERR_FILENO) close(log_fd);
            dprintf(STDERR_FILENO,
                    "NFSU2 log unavailable (descriptor error %d); stderr redirection skipped.\n",
                    saved_errno);
            return;
        }
        if (log_fd != STDERR_FILENO) close(log_fd);

        char version[129], build[129], source_sha[129];
        copy_plist_field(@"CFBundleShortVersionString", version, sizeof version);
        copy_plist_field(@"CFBundleVersion", build, sizeof build);
        copy_plist_field(@"NFSRuntimeSourceSHA", source_sha, sizeof source_sha);
        dprintf(STDERR_FILENO,
                "NFSU2 runtime log started; app_version=%s app_build=%s runtime_source_sha=%s\n",
                version, build, source_sha);
    }
}

void nfs_game_session_prepare_log(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, redirect_runtime_stderr);
}

static void set_status_locked(int state, const char *message) {
    g_session_state = state;
    snprintf(g_session_status, sizeof g_session_status, "%s", message ? message : "");
}

static int fail_session(int error_code, const char *message,
                        char *diagnostic, size_t diagnostic_capacity) {
    fprintf(stderr, "runtime session failed: error=%d %s\n", error_code, message ? message : "");
    pthread_mutex_lock(&g_session_lock);
    g_pause_requested = 0;
    set_status_locked(NFS_GAME_SESSION_FAILED, message);
    pthread_cond_broadcast(&g_session_resume);
    copy_text(diagnostic, diagnostic_capacity, g_session_status);
    pthread_mutex_unlock(&g_session_lock);
    return error_code ? error_code : EIO;
}

static int verify_executable_and_roots(const char *executable_path,
                                       const char *asset_root,
                                       const char *save_root,
                                       char *diagnostic,
                                       size_t diagnostic_capacity) {
    if (!executable_path || !*executable_path || !asset_root || !*asset_root ||
        !save_root || !*save_root) {
        copy_text(diagnostic, diagnostic_capacity,
                  "Executable, game asset root, and save root are required.");
        return EINVAL;
    }

    @autoreleasepool {
        NSString *exePath = [NSString stringWithUTF8String:executable_path];
        NSString *rootPath = [NSString stringWithUTF8String:asset_root];
        NSString *savePath = [NSString stringWithUTF8String:save_root];
        if (!exePath || !rootPath || !savePath) {
            copy_text(diagnostic, diagnostic_capacity, "A sandbox path is not valid UTF-8.");
            return EINVAL;
        }

        NSString *standardExe = [exePath stringByStandardizingPath];
        NSString *standardRoot = [rootPath stringByStandardizingPath];
        NSString *exeDirectory = [standardExe stringByDeletingLastPathComponent];
        if (![exeDirectory isEqualToString:standardRoot] ||
            [[standardExe lastPathComponent] caseInsensitiveCompare:@"SPEED2.EXE"] != NSOrderedSame) {
            copy_text(diagnostic, diagnostic_capacity,
                      "The executable must be SPEED2.EXE inside the app sandbox game folder.");
            return EINVAL;
        }

        NSError *fileError = nil;
        NSData *image = [NSData dataWithContentsOfFile:standardExe
                                               options:NSDataReadingMappedIfSafe
                                                 error:&fileError];
        if (!image) {
            NSString *message = [NSString stringWithFormat:@"Could not read the saved executable: %@",
                                  fileError.localizedDescription ?: @"unknown file error"];
            copy_text(diagnostic, diagnostic_capacity, message.UTF8String);
            return EIO;
        }
        if (image.length != kExpectedExecutableSize) {
            copy_text(diagnostic, diagnostic_capacity,
                      "Saved SPEED2.EXE has an unsupported size; import the verified build again.");
            return EINVAL;
        }

        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(image.bytes, (CC_LONG)image.length, digest);
        char digest_hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
        for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i)
            snprintf(digest_hex + i * 2, 3, "%02x", digest[i]);
        digest_hex[sizeof digest_hex - 1] = '\0';
        if (strcmp(digest_hex, kExpectedExecutableSHA256) != 0) {
            copy_text(diagnostic, diagnostic_capacity,
                      "Saved SPEED2.EXE failed SHA-256 authentication.");
            return EINVAL;
        }

        NSFileManager *manager = [NSFileManager defaultManager];
        BOOL isDirectory = NO;
        if (![manager fileExistsAtPath:standardRoot isDirectory:&isDirectory] || !isDirectory) {
            copy_text(diagnostic, diagnostic_capacity,
                      "The sandbox game asset directory is missing.");
            return ENOENT;
        }
        NSError *directoryError = nil;
        if (![manager createDirectoryAtPath:savePath
                 withIntermediateDirectories:YES
                                  attributes:nil
                                       error:&directoryError]) {
            NSString *message = [NSString stringWithFormat:@"Could not create the sandbox save directory: %@",
                                  directoryError.localizedDescription ?: @"unknown file error"];
            copy_text(diagnostic, diagnostic_capacity, message.UTF8String);
            return EACCES;
        }
    }
    return 0;
}

void nfs_game_session_checkpoint(void) {
    /* Presentation callbacks must never block UIKit's main thread while the
     * scene is inactive; only guest/runtime workers wait at this checkpoint.
     */
    if (pthread_main_np()) return;

    pthread_mutex_lock(&g_session_lock);
    while (g_session_started && g_pause_requested &&
           g_session_state != NFS_GAME_SESSION_FAILED &&
           g_session_state != NFS_GAME_SESSION_EXITED) {
        pthread_cond_wait(&g_session_resume, &g_session_lock);
    }
    pthread_mutex_unlock(&g_session_lock);
}

void nfs_game_session_set_active(int active) {
    if (!active) {
        /* Release every digital control and cursor before pausing the guest. */
        nfsu2_input_clear_all();
        nfsu2_input_set_cursor_available(false);
    }

    pthread_mutex_lock(&g_session_lock);
    g_session_active = active ? 1 : 0;
    if (g_session_started &&
        g_session_state != NFS_GAME_SESSION_FAILED &&
        g_session_state != NFS_GAME_SESSION_EXITED) {
        if (g_session_active) {
            g_pause_requested = 0;
            set_status_locked(NFS_GAME_SESSION_RUNNING,
                "Full runtime active; persistent guest worker retained. No real game frame is verified.");
            pthread_cond_broadcast(&g_session_resume);
        } else {
            g_pause_requested = 1;
            set_status_locked(NFS_GAME_SESSION_PAUSE_REQUESTED,
                "App inactive; guest pause requested at safe checkpoints. Session memory is retained.");
        }
    }
    pthread_mutex_unlock(&g_session_lock);
}

int nfs_game_session_get_state(void) {
    pthread_mutex_lock(&g_session_lock);
    int state = g_session_state;
    pthread_mutex_unlock(&g_session_lock);
    return state;
}

void nfs_game_session_get_status(char *diagnostic, size_t diagnostic_capacity) {
    pthread_mutex_lock(&g_session_lock);
    long frames = metal_frames(), triangles = metal_tris(), textures = metal_tex_uploaded();
    if (diagnostic && diagnostic_capacity)
        snprintf(diagnostic, diagnostic_capacity, "%s\nRenderer: %ld presents / %ld triangles / %ld texture uploads (scene unverified)",
                 g_session_status, frames, triangles, textures);
    static long logged_frames = -1, logged_triangles = -1, logged_textures = -1;
    if (frames != logged_frames || triangles != logged_triangles || textures != logged_textures) {
        fprintf(stderr, "runtime evidence: presents=%ld triangles=%ld textures_uploaded=%ld; actual scene/device validation pending\n",
                frames, triangles, textures);
        logged_frames = frames; logged_triangles = triangles; logged_textures = textures;
    }
    pthread_mutex_unlock(&g_session_lock);
}

void nfs_game_session_get_log_path(char *path, size_t path_capacity) {
    if (!path || path_capacity == 0) return;
    path[0] = '\0';
    @autoreleasepool {
        NSString *log_path = runtime_log_path();
        if (log_path) copy_text(path, path_capacity, log_path.fileSystemRepresentation);
    }
}

static void *guest_entry_thread(void *unused) {
    (void)unused;
    pthread_setname_np("NFSU2 guest");
    mem_altstack_install();

    /* A Win32 ExitProcess/ExitThread may longjmp from generated code. The
     * volatile flag survives setjmp/longjmp and releases the legacy guest
     * lock exactly once; guest RAM stays mapped for the process lifetime.
     */
    volatile int guest_lock_held = 0;
    int exit_code = setjmp(g_exit_jmp);
    if (exit_code == 0) {
        g_exit_armed = 1;
        guest_lock(&g_primary_cpu);
        guest_lock_held = 1;
        CPU *c = &g_primary_cpu;
        PUSH32(0xDEADC0DEu);
        sub_0075bcc7(c);
    } else {
        g_exit_armed = 0;
    }

    if (guest_lock_held) {
        guest_unlock();
        guest_lock_held = 0;
    }
    g_exit_armed = 0;

    char final_status[256];
    if (exit_code != 0) {
        snprintf(final_status, sizeof final_status,
                 "Guest process exited with code %d. Session memory is retained; no game frame is verified.",
                 g_exit_code);
    } else {
        snprintf(final_status, sizeof final_status,
                 "Guest entry returned (EIP=0x%08x). Session memory is retained; no game frame is verified.",
                 g_primary_cpu.eip);
    }
    pthread_mutex_lock(&g_session_lock);
    g_pause_requested = 0;
    set_status_locked(NFS_GAME_SESSION_EXITED, final_status);
    pthread_cond_broadcast(&g_session_resume);
    pthread_mutex_unlock(&g_session_lock);
    return NULL;
}

int nfs_game_session_start(const char *executable_path,
                           const char *asset_root,
                           const char *save_root,
                           char *diagnostic,
                           size_t diagnostic_capacity) {
    pthread_mutex_lock(&g_session_lock);
    if (g_session_state != NFS_GAME_SESSION_IDLE) {
        copy_text(diagnostic, diagnostic_capacity, g_session_status);
        int result = (g_session_state == NFS_GAME_SESSION_RUNNING ||
                      g_session_state == NFS_GAME_SESSION_PAUSE_REQUESTED) ? 0 : EALREADY;
        pthread_mutex_unlock(&g_session_lock);
        return result;
    }
    g_session_started = 1;
    set_status_locked(NFS_GAME_SESSION_PREPARING,
        "Authenticating SPEED2.EXE and preparing the full guest runtime...");
    pthread_mutex_unlock(&g_session_lock);

    char local_diagnostic[512] = {0};
    int rc = verify_executable_and_roots(executable_path, asset_root, save_root,
                                         local_diagnostic, sizeof local_diagnostic);
    if (rc) return fail_session(rc, local_diagnostic, diagnostic, diagnostic_capacity);

    /* Capture subsequent runtime stderr in an append-only, user-accessible file. */
    nfs_game_session_prepare_log();

    if (!metal_available() || !metal_window_ready()) {
        return fail_session(ENODEV,
            "The real Metal device or CAMetalLayer is not ready; the guest was not started.",
            diagnostic, diagnostic_capacity);
    }

    /* Match tests/boot.c's complete runtime path. The iOS view has already
     * attached the real CAMetalLayer on the main thread before this worker
     * maps the image or initializes COM resources.
     */
    mem_fault_handler_install();
    if (mem_load_pe(executable_path) != 0) {
        snprintf(local_diagnostic, sizeof local_diagnostic,
                 "Full runtime PE load failed (errno=%d: %s).",
                 errno, strerror(errno));
        return fail_session(EIO, local_diagnostic, diagnostic, diagnostic_capacity);
    }

    fileio_set_root(executable_path);
    fileio_set_write_root(save_root);
    dispatch_init();
    fprintf(stderr, "runtime policy: one legacy Win32/COM process; unknown imports return zero and unsupported instructions may continue. Compatibility fallbacks are logged; full Windows fidelity is unverified.\n");
    win32_init();
    overrides_install();

    GuestPEImage loaded = {
        .image_base = g_image_base,
        .image_size = g_image_size,
        .entry_point = g_image_entry
    };
    rc = guest_bootstrap_init(&g_primary_cpu, &loaded);
    if (rc) {
        snprintf(local_diagnostic, sizeof local_diagnostic,
                 "Guest CPU/TEB/PEB/stack setup failed (error %d).", rc);
        return fail_session(rc, local_diagnostic, diagnostic, diagnostic_capacity);
    }
    g_cur_cpu = &g_primary_cpu;

    pthread_attr_t attributes;
    rc = pthread_attr_init(&attributes);
    if (rc) {
        snprintf(local_diagnostic, sizeof local_diagnostic,
                 "Could not initialize the guest worker attributes (error %d).", rc);
        return fail_session(rc, local_diagnostic, diagnostic, diagnostic_capacity);
    }
    rc = pthread_attr_setstacksize(&attributes, NFS_GAME_GUEST_STACK_BYTES);
    if (rc == 0) rc = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (rc == 0) rc = pthread_attr_set_qos_class_np(&attributes, QOS_CLASS_USER_INTERACTIVE, 0);
    if (rc) {
        pthread_attr_destroy(&attributes);
        snprintf(local_diagnostic, sizeof local_diagnostic,
                 "Could not configure the %u MiB iOS guest stack/QoS (error %d).",
                 NFS_GAME_GUEST_STACK_BYTES / (1024u * 1024u), rc);
        return fail_session(rc, local_diagnostic, diagnostic, diagnostic_capacity);
    }

    pthread_mutex_lock(&g_session_lock);
    if (g_session_active) {
        set_status_locked(NFS_GAME_SESSION_RUNNING,
            "Full runtime initialized; starting guest entry on a 16 MiB worker stack. No real game frame is verified.");
    } else {
        g_pause_requested = 1;
        set_status_locked(NFS_GAME_SESSION_PAUSE_REQUESTED,
            "Full runtime initialized while app inactive; guest waits at its first safe checkpoint.");
    }
    pthread_mutex_unlock(&g_session_lock);

    pthread_t thread;
    rc = pthread_create(&thread, &attributes, guest_entry_thread, NULL);
    pthread_attr_destroy(&attributes);
    if (rc) {
        snprintf(local_diagnostic, sizeof local_diagnostic,
                 "Could not create the persistent guest worker (error %d). Guest memory is retained.", rc);
        return fail_session(rc, local_diagnostic, diagnostic, diagnostic_capacity);
    }

    pthread_mutex_lock(&g_session_lock);
    g_guest_thread_created = 1;
    copy_text(diagnostic, diagnostic_capacity, g_session_status);
    pthread_mutex_unlock(&g_session_lock);
    return 0;
}

#else

int nfs_game_session_start(const char *executable_path,
                           const char *asset_root,
                           const char *save_root,
                           char *diagnostic,
                           size_t diagnostic_capacity) {
    (void)executable_path;
    (void)asset_root;
    (void)save_root;
    copy_text(diagnostic, diagnostic_capacity,
              "This build contains diagnostics only; the full game runtime is not enabled.");
    return ENOTSUP;
}

void nfs_game_session_set_active(int active) { (void)active; }
void nfs_game_session_checkpoint(void) { }
void nfs_game_session_prepare_log(void) { }
int nfs_game_session_get_state(void) { return NFS_GAME_SESSION_IDLE; }
void nfs_game_session_get_status(char *diagnostic, size_t diagnostic_capacity) {
    copy_text(diagnostic, diagnostic_capacity,
              "This build contains diagnostics only; the full game runtime is not enabled.");
}

void nfs_game_session_get_log_path(char *path, size_t path_capacity) {
    copy_text(path, path_capacity, "");
}

#endif
