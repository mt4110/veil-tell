#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xpc/xpc.h>

#ifdef XPC_RECEIVER
static int forward(const char *token) {
    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons(TCP_PORT);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int sent = connect(fd, (const struct sockaddr *)&target, sizeof(target)) == 0
        && dprintf(fd, "%s\n", token) > 0;
    close(fd);
    return sent;
}

static void receive_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
        if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
        const char *token = xpc_dictionary_get_string(message, "token");
        if (!token || strlen(token) > 80 || strchr(token, '\n')) return;
        int stopping = strcmp(token, "stop-fixture") == 0;
        if (!stopping) {
            FILE *file = fopen(RECEIVER_LOG, "a");
            if (!file) return;
            int written = fprintf(file, "%s\n", token);
            if (fclose(file) != 0 || written <= 0 || !forward(token)) return;
        }
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        if (!reply) return;
        xpc_dictionary_set_string(reply, "ack", token);
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);
        if (stopping) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 5),
                           dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{ exit(0); });
        }
    });
    xpc_connection_resume(peer);
}

int main(void) {
    xpc_main(receive_peer);
    return 1;
}
#else
static CFDataRef receive_mach(CFMessagePortRef port, SInt32 message, CFDataRef data, void *context) {
    (void)port;
    (void)message;
    CFIndex size = CFDataGetLength(data);
    if (size < 1 || size > 80) return NULL;
    FILE *file = fopen(context, "a");
    if (!file) return NULL;
    size_t written = fwrite(CFDataGetBytePtr(data), 1, (size_t)size, file);
    fputc('\n', file);
    return fclose(file) == 0 && written == (size_t)size ? CFRetain(data) : NULL;
}

static int register_mach(CFStringRef name, char *path, int listen) {
    CFMessagePortContext context = {0, path, NULL, NULL, NULL};
    CFMessagePortRef port = CFMessagePortCreateLocal(NULL, name, receive_mach, &context, NULL);
    if (!port) {
        puts("mach_receiver=unavailable");
        return 12;
    }
    if (!listen) {
        puts("mach_receiver=registered");
        CFMessagePortInvalidate(port);
        CFRelease(port);
        return 0;
    }
    CFRunLoopSourceRef source = CFMessagePortCreateRunLoopSource(NULL, port, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    puts("mach_receiver=ready");
    fflush(stdout);
    CFRunLoopRun();
    return 0;
}

static int send_mach(CFStringRef name, const char *token) {
    CFMessagePortRef port = CFMessagePortCreateRemote(NULL, name);
    if (!port) {
        puts("mach_reply=unavailable");
        return 11;
    }
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, strlen(token));
    CFDataRef reply = NULL;
    SInt32 status = CFMessagePortSendRequest(port, 1, data, 2, 2, kCFRunLoopDefaultMode, &reply);
    int ack = status == kCFMessagePortSuccess && reply && CFEqual(data, reply);
    printf("mach_reply=%s status=%d\n", ack ? "ACK" : "failed", (int)status);
    return ack ? 0 : 10;
}

static int send_xpc(const char *name, const char *token) {
    xpc_connection_t connection = xpc_connection_create(name, NULL);
    if (!connection) return 65;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) { (void)event; });
    xpc_connection_resume(connection);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int status = 13;
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "token", token);
    xpc_connection_send_message_with_reply(connection, message, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(xpc_object_t result) {
        if (result == XPC_ERROR_CONNECTION_INVALID) {
            puts("xpc_reply=connection_invalid");
            status = 11;
        } else if (xpc_get_type(result) == XPC_TYPE_DICTIONARY) {
            const char *reply = xpc_dictionary_get_string(result, "ack");
            if (reply && strcmp(reply, token) == 0) {
                puts("xpc_reply=ACK");
                status = 0;
            }
        }
        dispatch_semaphore_signal(done);
    });
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC))) {
        puts("xpc_reply=timeout");
        return 10;
    }
    return status;
}

int main(int argc, char **argv) {
    if (argc != 4) return 64;
    if (strcmp(argv[1], "send-xpc") == 0) return send_xpc(argv[2], argv[3]);
    CFStringRef name = CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingUTF8);
    if (!name) return 65;
    if (strcmp(argv[1], "listen-mach") == 0) return register_mach(name, argv[3], 1);
    if (strcmp(argv[1], "register-mach") == 0) return register_mach(name, argv[3], 0);
    if (strcmp(argv[1], "send-mach") == 0) return send_mach(name, argv[3]);
    return 64;
}
#endif
