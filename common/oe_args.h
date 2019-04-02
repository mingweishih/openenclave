// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#ifndef OE_ARGS_H
#define OE_ARGS_H

#include <stdint.h>
#include <stdlib.h> /* for wchar_t */

#include <openenclave/bits/result.h>

#include "openenclave/bits/defs.h"
#include "openenclave/bits/types.h"

/* User types specified in edl */
typedef struct oe_hostfs_dirent_struct
{
    uint64_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[256];
} oe_hostfs_dirent_struct;

typedef struct oe_hostfs_timespec_struct
{
    time_t tv_sec;
    suseconds_t tv_nsec;
} oe_hostfs_timespec_struct;

typedef struct oe_hostfs_stat_struct
{
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct oe_hostfs_timespec_struct st_atim;
    struct oe_hostfs_timespec_struct st_mtim;
    struct oe_hostfs_timespec_struct st_ctim;
} oe_hostfs_stat_struct;

typedef struct _public_root_ecall_args_t
{
    oe_result_t _result;
} public_root_ecall_args_t;

typedef struct _oe_polling_notify_args_t
{
    int _retval;
    struct oe_device_notifications* notifications;
    size_t num_notifications;
    oe_result_t _result;
} oe_polling_notify_args_t;

typedef struct _oe_hostfs_open_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    int flags;
    mode_t mode;
    int* err;
    oe_result_t _result;
} oe_hostfs_open_args_t;

typedef struct _oe_hostfs_read_args_t
{
    ssize_t _retval;
    int fd;
    void* buf;
    size_t count;
    int* err;
    oe_result_t _result;
} oe_hostfs_read_args_t;

typedef struct _oe_hostfs_write_args_t
{
    ssize_t _retval;
    int fd;
    void* buf;
    size_t count;
    int* err;
    oe_result_t _result;
} oe_hostfs_write_args_t;

typedef struct _oe_hostfs_lseek_args_t
{
    off_t _retval;
    int fd;
    off_t offset;
    int whence;
    int* err;
    oe_result_t _result;
} oe_hostfs_lseek_args_t;

typedef struct _oe_hostfs_close_args_t
{
    int _retval;
    int fd;
    int* err;
    oe_result_t _result;
} oe_hostfs_close_args_t;

typedef struct _oe_hostfs_dup_args_t
{
    int _retval;
    int oldfd;
    int* err;
    oe_result_t _result;
} oe_hostfs_dup_args_t;

typedef struct _oe_hostfs_opendir_args_t
{
    void* _retval;
    char* name;
    size_t name_len;
    int* err;
    oe_result_t _result;
} oe_hostfs_opendir_args_t;

typedef struct _oe_hostfs_readdir_args_t
{
    int _retval;
    void* dirp;
    struct oe_hostfs_dirent_struct* ent;
    int* err;
    oe_result_t _result;
} oe_hostfs_readdir_args_t;

typedef struct _oe_hostfs_rewinddir_args_t
{
    void* dirp;
    oe_result_t _result;
} oe_hostfs_rewinddir_args_t;

typedef struct _oe_hostfs_closedir_args_t
{
    int _retval;
    void* dirp;
    int* err;
    oe_result_t _result;
} oe_hostfs_closedir_args_t;

typedef struct _oe_hostfs_stat_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    struct oe_hostfs_stat_struct* buf;
    int* err;
    oe_result_t _result;
} oe_hostfs_stat_args_t;

typedef struct _oe_hostfs_access_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    int mode;
    int* err;
    oe_result_t _result;
} oe_hostfs_access_args_t;

typedef struct _oe_hostfs_link_args_t
{
    int _retval;
    char* oldpath;
    size_t oldpath_len;
    char* newpath;
    size_t newpath_len;
    int* err;
    oe_result_t _result;
} oe_hostfs_link_args_t;

typedef struct _oe_hostfs_unlink_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    int* err;
    oe_result_t _result;
} oe_hostfs_unlink_args_t;

typedef struct _oe_hostfs_rename_args_t
{
    int _retval;
    char* oldpath;
    size_t oldpath_len;
    char* newpath;
    size_t newpath_len;
    int* err;
    oe_result_t _result;
} oe_hostfs_rename_args_t;

typedef struct _oe_hostfs_truncate_args_t
{
    int _retval;
    char* path;
    size_t path_len;
    off_t length;
    int* err;
    oe_result_t _result;
} oe_hostfs_truncate_args_t;

typedef struct _oe_hostfs_mkdir_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    mode_t mode;
    int* err;
    oe_result_t _result;
} oe_hostfs_mkdir_args_t;

typedef struct _oe_hostfs_rmdir_args_t
{
    int _retval;
    char* pathname;
    size_t pathname_len;
    int* err;
    oe_result_t _result;
} oe_hostfs_rmdir_args_t;

typedef struct _oe_hostsock_socket_args_t
{
    int _retval;
    int domain;
    int type;
    int protocol;
    int* err;
    oe_result_t _result;
} oe_hostsock_socket_args_t;

typedef struct _oe_hostsock_socketpair_args_t
{
    int _retval;
    int domain;
    int type;
    int protocol;
    int* sv;
    int* err;
    oe_result_t _result;
} oe_hostsock_socketpair_args_t;

typedef struct _oe_hostsock_connect_args_t
{
    int _retval;
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen;
    int* err;
    oe_result_t _result;
} oe_hostsock_connect_args_t;

typedef struct _oe_hostsock_accept_args_t
{
    int _retval;
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen_in;
    socklen_t* addrlen_out;
    int* err;
    oe_result_t _result;
} oe_hostsock_accept_args_t;

typedef struct _oe_hostsock_bind_args_t
{
    int _retval;
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen;
    int* err;
    oe_result_t _result;
} oe_hostsock_bind_args_t;

typedef struct _oe_hostsock_listen_args_t
{
    int _retval;
    int sockfd;
    int backlog;
    int* err;
    oe_result_t _result;
} oe_hostsock_listen_args_t;

typedef struct _oe_hostsock_recvmsg_args_t
{
    ssize_t _retval;
    int sockfd;
    void* msg_name;
    socklen_t msg_namelen_in;
    socklen_t* msg_namelen_out;
    struct iovec* msg_iov;
    size_t msg_iovlen_in;
    size_t* msg_iovlen_out;
    void* msg_control;
    size_t msg_controllen_in;
    size_t* msg_controllen_out;
    int msg_flags_in;
    int* msg_flags_out;
    int flags;
    int* err;
    oe_result_t _result;
} oe_hostsock_recvmsg_args_t;

typedef struct _oe_hostsock_sendmsg_args_t
{
    ssize_t _retval;
    int sockfd;
    void* msg_name;
    socklen_t msg_namelen;
    struct iovec* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    int msg_flags;
    int flags;
    int* err;
    oe_result_t _result;
} oe_hostsock_sendmsg_args_t;

typedef struct _oe_hostsock_recv_args_t
{
    ssize_t _retval;
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    int* err;
    oe_result_t _result;
} oe_hostsock_recv_args_t;

typedef struct _oe_hostsock_recvfrom_args_t
{
    ssize_t _retval;
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    struct sockaddr* src_addr;
    socklen_t addrlen_in;
    socklen_t* addrlen_out;
    int* err;
    oe_result_t _result;
} oe_hostsock_recvfrom_args_t;

typedef struct _oe_hostsock_send_args_t
{
    ssize_t _retval;
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    int* err;
    oe_result_t _result;
} oe_hostsock_send_args_t;

typedef struct _oe_hostsock_sendto_args_t
{
    ssize_t _retval;
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    struct sockaddr* dest_addr;
    socklen_t addrlen;
    int* err;
    oe_result_t _result;
} oe_hostsock_sendto_args_t;

typedef struct _oe_hostsock_shutdown_args_t
{
    int _retval;
    int sockfd;
    int how;
    int* err;
    oe_result_t _result;
} oe_hostsock_shutdown_args_t;

typedef struct _oe_hostsock_close_args_t
{
    int _retval;
    int fd;
    int* err;
    oe_result_t _result;
} oe_hostsock_close_args_t;

typedef struct _oe_hostsock_dup_args_t
{
    int _retval;
    int oldfd;
    int* err;
    oe_result_t _result;
} oe_hostsock_dup_args_t;

typedef struct _oe_hostsock_setsockopt_args_t
{
    int _retval;
    int sockfd;
    int level;
    int optname;
    void* optval;
    socklen_t optlen;
    int* err;
    oe_result_t _result;
} oe_hostsock_setsockopt_args_t;

typedef struct _oe_hostsock_getsockopt_args_t
{
    int _retval;
    int sockfd;
    int level;
    int optname;
    void* optval;
    socklen_t optlen_in;
    socklen_t* optlen_out;
    int* err;
    oe_result_t _result;
} oe_hostsock_getsockopt_args_t;

typedef struct _oe_hostsock_getsockname_args_t
{
    int _retval;
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen_in;
    socklen_t* addrlen_out;
    int* err;
    oe_result_t _result;
} oe_hostsock_getsockname_args_t;

typedef struct _oe_hostsock_getpeername_args_t
{
    int _retval;
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen_in;
    socklen_t* addrlen_out;
    int* err;
    oe_result_t _result;
} oe_hostsock_getpeername_args_t;

typedef struct _oe_hostsock_shutdown_device_args_t
{
    int _retval;
    int sockfd;
    int* err;
    oe_result_t _result;
} oe_hostsock_shutdown_device_args_t;

typedef struct _oe_polling_epoll_create1_args_t
{
    int _retval;
    int flags;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_create1_args_t;

typedef struct _oe_polling_epoll_wait_args_t
{
    int _retval;
    int64_t enclaveid;
    int epfd;
    struct epoll_event* events;
    size_t maxevents;
    int timeout;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_wait_args_t;

typedef struct _oe_polling_epoll_ctl_add_args_t
{
    int _retval;
    int epfd;
    int fd;
    unsigned int event_mask;
    int list_idx;
    int epoll_enclave_fd;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_ctl_add_args_t;

typedef struct _oe_polling_epoll_ctl_del_args_t
{
    int _retval;
    int epfd;
    int fd;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_ctl_del_args_t;

typedef struct _oe_polling_epoll_ctl_mod_args_t
{
    int _retval;
    int epfd;
    int fd;
    unsigned int event_mask;
    int list_idx;
    int epoll_enclave_fd;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_ctl_mod_args_t;

typedef struct _oe_polling_epoll_close_args_t
{
    int _retval;
    int fd;
    int* err;
    oe_result_t _result;
} oe_polling_epoll_close_args_t;

typedef struct _oe_polling_shutdown_device_args_t
{
    int _retval;
    int fd;
    int* err;
    oe_result_t _result;
} oe_polling_shutdown_device_args_t;

/* trusted function ids */
enum
{
    fcn_id_public_root_ecall = 0,
    fcn_id_oe_polling_notify = 1,
    fcn_id_trusted_call_id_max = OE_ENUM_MAX
};

/* untrusted function ids */
enum
{
    fcn_id_oe_hostfs_open = 0,
    fcn_id_oe_hostfs_read = 1,
    fcn_id_oe_hostfs_write = 2,
    fcn_id_oe_hostfs_lseek = 3,
    fcn_id_oe_hostfs_close = 4,
    fcn_id_oe_hostfs_dup = 5,
    fcn_id_oe_hostfs_opendir = 6,
    fcn_id_oe_hostfs_readdir = 7,
    fcn_id_oe_hostfs_rewinddir = 8,
    fcn_id_oe_hostfs_closedir = 9,
    fcn_id_oe_hostfs_stat = 10,
    fcn_id_oe_hostfs_access = 11,
    fcn_id_oe_hostfs_link = 12,
    fcn_id_oe_hostfs_unlink = 13,
    fcn_id_oe_hostfs_rename = 14,
    fcn_id_oe_hostfs_truncate = 15,
    fcn_id_oe_hostfs_mkdir = 16,
    fcn_id_oe_hostfs_rmdir = 17,
    fcn_id_oe_hostsock_socket = 18,
    fcn_id_oe_hostsock_socketpair = 19,
    fcn_id_oe_hostsock_connect = 20,
    fcn_id_oe_hostsock_accept = 21,
    fcn_id_oe_hostsock_bind = 22,
    fcn_id_oe_hostsock_listen = 23,
    fcn_id_oe_hostsock_recvmsg = 24,
    fcn_id_oe_hostsock_sendmsg = 25,
    fcn_id_oe_hostsock_recv = 26,
    fcn_id_oe_hostsock_recvfrom = 27,
    fcn_id_oe_hostsock_send = 28,
    fcn_id_oe_hostsock_sendto = 29,
    fcn_id_oe_hostsock_shutdown = 30,
    fcn_id_oe_hostsock_close = 31,
    fcn_id_oe_hostsock_dup = 32,
    fcn_id_oe_hostsock_setsockopt = 33,
    fcn_id_oe_hostsock_getsockopt = 34,
    fcn_id_oe_hostsock_getsockname = 35,
    fcn_id_oe_hostsock_getpeername = 36,
    fcn_id_oe_hostsock_shutdown_device = 37,
    fcn_id_oe_polling_epoll_create1 = 38,
    fcn_id_oe_polling_epoll_wait = 39,
    fcn_id_oe_polling_epoll_ctl_add = 40,
    fcn_id_oe_polling_epoll_ctl_del = 41,
    fcn_id_oe_polling_epoll_ctl_mod = 42,
    fcn_id_oe_polling_epoll_close = 43,
    fcn_id_oe_polling_shutdown_device = 44,
    fcn_id_untrusted_call_max = OE_ENUM_MAX
};

#endif // OE_ARGS_H
