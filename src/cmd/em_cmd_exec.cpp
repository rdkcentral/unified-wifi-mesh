/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_cli.h"

void em_cmd_exec_t::wait(struct timespec *time_to_wait)
{
    printf("Waiting\n");
    pthread_mutex_lock(&m_lock);
    //pthread_cond_timedwait(&m_cond, &m_lock, time_to_wait);
    pthread_cond_wait(&m_cond, &m_lock);
    printf("End Waiting\n");
}

void em_cmd_exec_t::release_wait()
{
    printf("Signaling\n");
    pthread_cond_signal(&m_cond);
    pthread_mutex_unlock(&m_lock);
}

int em_cmd_exec_t::load_params_file(const char *filename, char *buff)
{
    FILE *fp;
    char tmp[1024];
    int sz = 0;

    if ((fp = fopen(filename, "r")) == NULL) {
        printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, filename, errno);
        return -1;
    } else {

        //clear the data from buffer
        strncpy(buff, "", 1);
        while (fgets(tmp, sizeof(tmp), fp) != NULL) {
            strncat(buff, tmp, strlen(tmp));
            sz += static_cast<int> (strlen(tmp));
        }

        fclose(fp);
    }

    return sz;
}   

int em_cmd_exec_t::execute(em_cmd_type_t type, em_service_type_t to_svc, unsigned char *in, unsigned int len)
{
    em_event_t ev;
    em_bus_event_t *bevt;
    em_subdoc_info_t    *info;
    ev.type = em_event_type_bus;
    bevt = &ev.u.bevt;
    bevt->type = em_cmd_t::cmd_2_bus_event_type(type);
    info = &bevt->u.subdoc;
    memcpy(info->buff, in, len);
    
	return send_cmd(to_svc, reinterpret_cast<unsigned char *> (&ev), sizeof(em_event_t));;
}

unsigned short em_cmd_exec_t::get_port_from_dst_service(em_service_type_t to_svc)
{
	unsigned short port = 0;

    switch (to_svc) {
        case em_service_type_ctrl:
			port = EM_CTRL_PORT;
            break;

        case em_service_type_agent:
			port = EM_AGENT_PORT;
            break;

        case em_service_type_cli:
			port = 0;
            break;

        default:
			port = 0;
            break;
    }

    return port;
}

char *em_cmd_exec_t::get_path_from_dst_service(em_service_type_t to_svc, em_long_string_t sock_path)
{
    switch (to_svc) {
        case em_service_type_ctrl:
            snprintf(sock_path, sizeof(em_long_string_t), "%s_%s", EM_PATH_PREFIX, EM_CTRL_PATH);
            break;

        case em_service_type_agent:
            snprintf(sock_path, sizeof(em_long_string_t), "%s_%s", EM_PATH_PREFIX, EM_AGENT_PATH);
            break;

        case em_service_type_cli:
            snprintf(sock_path, sizeof(em_long_string_t), "%s_%s", EM_PATH_PREFIX, EM_CLI_PATH);
            break;

        default:
            return NULL;
            break;
    }

    return sock_path;
}

void em_cmd_exec_t::close_listener_socket(int sock, em_service_type_t svc)
{
#ifdef LOCAL_CLI
	em_long_string_t path;

    if (get_path_from_dst_service(svc, path) == NULL) {
        printf("%s:%d: Could not find path from destination service: %d\n", svc);
        return;
    }


	unlink(path);
#endif
	close(sock);
}

int em_cmd_exec_t::get_listener_socket(em_service_type_t svc)
{
#ifdef LOCAL_CLI
	struct sockaddr_un addr;
	em_long_string_t path;
	int domain = AF_UNIX;
#else
	struct sockaddr_in addr;
	unsigned short port;
	int domain = AF_INET;
#endif
	int lsock;
	ssize_t ret;

#ifdef LOCAL_CLI
    if (get_path_from_dst_service(svc, path) == NULL) {
#else
    if ((port = get_port_from_dst_service(svc)) == 0) {
#endif
        printf("%s:%d: Could not find path from destination service: %d\n", svc);
        return -1;
    }

#ifdef LOCAL_CLI
	unlink(path);
#endif

    if ((lsock = socket(domain, SOCK_STREAM, 0)) < 0) {
        printf("%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }   
   
    memset(&addr, 0, sizeof(addr));
#ifdef LOCAL_CLI 
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
#else
	addr.sin_family = AF_INET; 
    addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    addr.sin_port = htons(port);
#endif

    if ((ret = bind(lsock, reinterpret_cast<const struct sockaddr *> (&addr), sizeof(struct sockaddr_un))) == -1) {
        printf("%s:%d: bind error on socket: %d, err:%d\n", __func__, __LINE__, lsock, errno);
        return -1;
    }

	return lsock;
}

SSL *em_cmd_exec_t::get_ep_for_dst_svc(SSL_CTX *ctx, em_service_type_t svc)
{
	SSL *ssl;
#ifdef LOCAL_CLI
	struct sockaddr_un addr;
	em_long_string_t sock_path;
	int domain = AF_UNIX;
#else
	struct sockaddr_in addr;
	unsigned short port;
	int domain = AF_INET;
#endif
    int sock, ret;
	unsigned int sz = sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN;

    if ((sock = socket(domain, SOCK_STREAM, 0)) < 0) {
        printf("%s:%d: Could not create socket\n", __func__, __LINE__);
        return NULL;
    }

#ifdef LOCAL_CLI
    if (get_path_from_dst_service(svc, sock_path) == NULL) {
#else
    if ((port = get_port_from_dst_service(svc)) == 0) {
#endif
        printf("%s:%d: Could not find path from destination service: %d\n", svc);
		close(sock);
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
#ifdef LOCAL_CLI 
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
#else
	memcpy(&addr, get_ep_addr(), sizeof(struct sockaddr_in));
    addr.sin_port = htons(port);
#endif
    
	if ((ret = connect(sock, (const struct sockaddr *) &addr, sizeof(addr))) != 0) {
        printf("%s:%d: Could not connect to dest\n", __func__, __LINE__);
		close(sock);
        return NULL;
    }

	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer EM_MAX_EVENT_DATA_LEN
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer EM_MAX_EVENT_DATA_LEN
	
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
        printf("%s:%d: Could not create ssl\n", __func__, __LINE__);
		close(sock);
		return NULL;
	}
    SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) != 1) {
        printf("%s:%d: Could not connect to ssl\n", __func__, __LINE__);
    	SSL_free(ssl);
		close(sock);
		return NULL;
	}

	return ssl;
}

int em_cmd_exec_t::send_cmd(em_service_type_t to_svc, unsigned char *in, unsigned int in_len, char *out, unsigned int out_len)
{
	SSL *ssl;
#ifdef LOCAL_CLI
    struct sockaddr_un addr;
    em_long_string_t sock_path;
	int domain = AF_UNIX;
#else
	struct sockaddr_in addr;
	unsigned short port;
	int domain = AF_INET;
#endif
    int dsock;
    ssize_t ret;
    unsigned int sz = sizeof(em_event_t);

#ifdef LOCAL_CLI
    if (get_path_from_dst_service(to_svc, sock_path) == NULL) {
#else
    if ((port = get_port_from_dst_service(to_svc)) == 0) {
#endif
        printf("%s:%d: Could not find path from destination service: %d\n",__func__,__LINE__, to_svc);
        return -1;
    }
    
	if ((dsock = socket(domain, SOCK_STREAM, 0)) < 0) {
        snprintf(out, out_len, "%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    setsockopt(dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer 1K
    setsockopt(dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer 1K

    memset(&addr, 0, sizeof(addr));
#ifdef LOCAL_CLI 
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
#else
	addr.sin_family = AF_INET; 
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
#endif

    //snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if ((ret = connect(dsock, reinterpret_cast<const struct sockaddr *> (&addr), sizeof(struct sockaddr_un))) != 0) {
        snprintf(out, out_len, "%s:%d: connect error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    ssl = SSL_new(m_ssl_ctx);
    SSL_set_fd(ssl, dsock);

    if ((ret = SSL_write(ssl, in, in_len)) <= 0) {
    	SSL_free(ssl);
        close(dsock);
        return -1;
    }

    if (out == NULL) {
    	SSL_free(ssl);
        close(dsock);
        return 0;
    }
    
	/* Receive result. */
    if ((ret = SSL_read(ssl, reinterpret_cast<unsigned char *> (out), out_len)) <= 0) {
        snprintf(out, out_len, "%s:%d: result read error on socket, err:%d\n", __func__, __LINE__, errno);
    	SSL_free(ssl);
        close(dsock);
        return -1;
    }
    	
	SSL_free(ssl);
    close(dsock);

    return 0;
}

void em_cmd_exec_t::deinit()
{
	SSL_CTX_free(m_ssl_ctx); 
}

int em_cmd_exec_t::init()
{
	const SSL_METHOD *method;

    pthread_cond_init(&m_cond, NULL);
    pthread_mutex_init(&m_lock, NULL);

	OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
	method = TLSv1_2_server_method();
    if ((m_ssl_ctx = SSL_CTX_new(method)) == NULL) {
        printf("%s:%d: Failed to create SSL context\n", __func__, __LINE__);
		return -1;
    }
	
	SSL_CTX_set_cipher_list(m_ssl_ctx, "ALL:eNULL");

    if (SSL_CTX_load_verify_locations(m_ssl_ctx, EM_CERT_FILE, EM_KEY_FILE) != 1) {
		printf("%s:%d: Failed to verify certificate locations\n", __func__, __LINE__);
        SSL_CTX_free(m_ssl_ctx);
        return -1;
    }

    if (SSL_CTX_set_default_verify_paths(m_ssl_ctx) != 1) {
		printf("%s:%d: Failed to verify paths\n", __func__, __LINE__);
        SSL_CTX_free(m_ssl_ctx);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(m_ssl_ctx, EM_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("%s:%d: Failed to use certificate file\n", __func__, __LINE__);
        SSL_CTX_free(m_ssl_ctx);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ssl_ctx, EM_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("%s:%d: Failed to use private key file\n", __func__, __LINE__);
        SSL_CTX_free(m_ssl_ctx);
        return -1;
    }
	
	return 0;
}

em_cmd_exec_t::em_cmd_exec_t()
{

}

em_cmd_exec_t::~em_cmd_exec_t()
{

}
