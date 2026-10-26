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
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <pthread.h>
#include "web.h"
#include "em_base.h"

typedef struct {
    web_t *web;
    int sock;
} web_args_t;

char* web_t::parse(char line[], const char symbol[])
{
    char *copy = (char *)malloc(strlen(line) + 1);
    strcpy(copy, line);

    char *message;
    char * token = strtok(copy, symbol);
    int current = 0;

    while (token != NULL) {

        token = strtok(NULL, " ");
        if (current == 0) {
            message = token;
            return message;
        }
        current = current + 1;
    }
   
    free(token);
    free(copy);
   
    return NULL;
}

char* web_t::parse_method(char line[], const char symbol[])
{
    char *copy = (char *)malloc(strlen(line) + 1);
    strcpy(copy, line);

    char *message = NULL;
    char * token = strtok(copy, symbol);
    int current = 0;

    while (token != NULL) {

      //token = strtok(NULL, " ");
        if (current == 0) {
            message = token;
            return message;
        }
        current = current + 1;
    }
    free(copy);
    free(token);
    return NULL;
}

char* web_t::find_value(char *buff, const char *name, char *value)
{
    char *tmp, *start, *end;
    const char *delim = "\r\n";
    
    if ((tmp = strstr(buff, name)) == NULL) {
        return NULL;
    }
    start = tmp + strlen(name) + 1;
    if ((end = strstr(start, delim)) == NULL) {
        return NULL;
    }
    
    strncpy(value, start, (end - start));
    
    return value;
}

web_data_extn_type_t web_t::get_file_extension(const char *file_name)
{
    char *delim, *tmp;
    
    if ((delim = strchr((char *)file_name, '.')) == NULL) {
        return web_data_extn_type_none;
    }
    
    tmp = (char *)file_name;
    
    while ((delim = strchr(tmp, '.')) != NULL) {
        tmp = delim; tmp++;
    }
    
    // tmp points to the last '.'
    delim = tmp;

    if (strncmp(delim, "json", strlen("json")) == 0) {
        return web_data_extn_type_json;
    } else if (strncmp(delim, "js", strlen("js")) == 0) {
        return web_data_extn_type_js;
    } else if (strncmp(delim, "html", strlen("html")) == 0) {
        return web_data_extn_type_html;
    } else if (strncmp(delim, "css", strlen("css")) == 0) {
        return web_data_extn_type_css;
    } else if (strncmp(delim, "ico", strlen("ico")) == 0) {
        return web_data_extn_type_ico;
    } else if (strncmp(delim, "php", strlen("php")) == 0) {
        return web_data_extn_type_php;
    } else if (strncmp(delim, "jpg", strlen("jpg")) == 0) {
        return web_data_extn_type_jpg;
    } else if (strncmp(delim, "png", strlen("png")) == 0) {
        return web_data_extn_type_png;
    }
    
    return web_data_extn_type_none;
}

optimizer_event_type_t web_t::get_event_type(const char *action)
{
    optimizer_event_type_t type = optimizer_event_type_max;
    
    if (strncmp(action, "/analyze-csi", strlen("/analyze-csi")) == 0) {
        type = optimizer_event_type_de_change;
    } else if (strncmp(action, "/abort-csi", strlen("/abort-csi")) == 0) {
        type = optimizer_event_type_de_change;
    } else if (strncmp(action, "/save-csi", strlen("/save-csi")) == 0) {
        type = optimizer_event_type_de_change;
    } else if (strncmp(action, "/capture-csi", strlen("/capture-csi")) == 0) {
        type = optimizer_event_type_de_change;
    } else if (strncmp(action, "/motion-info-csi", strlen("/motion-info-csi")) == 0) {
        type = optimizer_event_type_de_change;
    }
    
    return type;
}

int web_t::send_message(int fd, web_data_extn_type_t data_type, bool file, const char *data)
{
    int fdfile;
    struct stat stat_buf;  /* hold information about input file */
    off_t total_size, offset = 0;
    off_t len = 0;
    char value[RESP_BUFF_SZ];
    char head[PATH_NAME_SZ] = {0};
    
    strncpy(head, m_http_header, strlen(m_http_header) + 1);
    
    switch (data_type) {
        case web_data_extn_type_plain:
            strcat(head, "Content-Type: text/plain\r\n");
            break;
        
        case web_data_extn_type_html:
            strcat(head, "Content-Type: text/html\r\n");
            break;
            
        case web_data_extn_type_js:
            strcat(head, "Content-Type: text/javascript\r\n");
            break;
            
        case web_data_extn_type_css:
            strcat(head, "Content-Type: text/css\r\n");
            break;
       
        case web_data_extn_type_json:
            strcat(head, "Content-Type: application/json\r\n");
            break;
            
        case web_data_extn_type_ico:
            strcat(head, "Content-Type: image/vnd.microsoft.icon\r\n");
            break;
            
        case web_data_extn_type_jpg:
            strcat(head, "Content-Type: image/jpeg\r\n");
            break;
            
        case web_data_extn_type_png:
            strcat(head, "Content-Type: image/png\r\n");
            break;
            
        case web_data_extn_type_php:
            strcat(head, "Content-Type: text/plain\r\n");
            break;
            
        default:
            strcat(head, "Content-Type: text/plain\r\n");
    }
   
    if (file == false) {
        snprintf(value, sizeof(value), "Content-Length: %zu\r\n\r\n", strlen(data));
        strcat(head, value);
        write(fd, head, strlen(head));
        write(fd, data, strlen(data));
        return 0;
    }

    if((fdfile = open(data, O_RDONLY)) < 0){
        printf("%s:%d: Cannot Open file path :%s with error %d\n", __func__, __LINE__, data, fdfile);
        snprintf(value, sizeof(value), "Content-Length: 0");
        strcat(head, value);
        write(fd, head, strlen(head));
        return -1;
    }

    fstat(fdfile, &stat_buf);
    total_size = stat_buf.st_size;
    snprintf(value, sizeof(value), "Content-Length: %lld\r\n\r\n", total_size);
    strcat(head, value);
    write(fd, head, strlen(head));
    
    while (offset < total_size) {
        len = total_size - offset;
        if (sendfile(fd, fdfile, &offset, len) != 0) {
            //printf("%s:%d: send file error:%d\n", __func__, __LINE__, errno);
            close(fdfile);
            return -1;
        }
        offset += len;
    }
    
    close(fdfile);
    
    return 0;
}
    
void web_t::handle_get(int sock, const char *action_string)
{
    web_data_extn_type_t extn_type;
    char file_name[PATH_NAME_SZ] = {0};
    char *tmp;
    char *buff;
    
    strncpy(file_name, m_head, strlen(m_head) + 1);
    printf("%s:%d: Action: %s\n", __func__, __LINE__, action_string);
    
    if (strlen(action_string) <= 1) {
        strcat(file_name, "/index.html");
        send_message(sock, web_data_extn_type_html, true, file_name);
    } else if ((tmp = strchr((char *)action_string, '/')) != NULL) {
        tmp++;
        extn_type = get_file_extension(tmp);
        if (extn_type == web_data_extn_type_none) {
            printf("%s:%d: Unknown file extension\n", __func__, __LINE__); 
            
        } else if (extn_type == web_data_extn_type_json) {
            if (strncmp(tmp, "Topology", strlen("Topology")) == 0) {
                buff = (char *)malloc(EM_LONG_IO_BUFF_SZ);
                send_message(sock, extn_type, false, handle_get(optimizer_event_type_get_topology, buff, EM_LONG_IO_BUFF_SZ));
                free(buff);
            } else if (strncmp(tmp, "DataElements", strlen("DataElements")) == 0) {
                printf("%s:%d: Loding data elements ...\n", __func__, __LINE__);
                buff = (char *)malloc(EM_LONG_IO_BUFF_SZ);
                send_message(sock, extn_type, false, handle_get(optimizer_event_type_get_de, buff, EM_LONG_IO_BUFF_SZ));
                free(buff);

            }
        } else {
            //send real file
            strcat(file_name, action_string);
            send_message(sock, extn_type, true, file_name);
        }
    }
}
    
void web_t::handle_post(int sock, const char *action_string, char *buffer)
{
    
}

int web_t::server(int sock)
{
    char buffer[30000] = {0};
    long valread;
    char *method, *action;
   
    valread = read(sock, buffer, sizeof(buffer));
    if ((method = parse_method(buffer, " ")) == NULL) {  //Try to get the path which the client ask for
        return NULL;
    }

    if ((action = parse(buffer, " ")) == NULL) {
        return NULL;
    }
    
    printf("%s:%d: Method: %s\tString: %s\n", __func__, __LINE__, method, action);
    
    if (strncmp(method, "GET", strlen("GET")) == 0) {
        handle_get(sock, action);
    } else if (strncmp(method, "POST", strlen("POST")) == 0) {
        handle_post(sock, action, buffer);
    }
    close(sock);

    return 0;
}

void *web_t::server(void *arg)
{
    web_args_t *args = (web_args_t *)arg;
    web_t *web = args->web;
    
    web->server(args->sock);
    
    return NULL;
}



int web_t::run()
{
    web_args_t args;
    pthread_t stid;
    pthread_attr_t attr;
    size_t stack_size = 1024 * 1024; // Example: 1 MB stack size
    int new_sock;
    int addrlen = sizeof(m_address);
   
    while (m_exit == false) {
        if ((new_sock = accept(m_server_fd, (struct sockaddr *)&m_address, (socklen_t*)&addrlen))<0) {
            printf("%s:%d: Error in accept: %d\n", __func__, __LINE__, errno);
            return -1;
        }
    
        args.web = this;
        args.sock = new_sock;
        
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, stack_size);
        if (pthread_create(&stid, &attr, server, &args) != 0) {
            printf("%s:%d: Failed to start child thread\n", __func__, __LINE__);
            return -1;
        }
    }
    
    return 0;
}

void *web_t::run(void *arg)
{
    
    web_t *web = (web_t *)arg;
    
    web->run();
    
    return NULL;
}

void web_t::stop()
{
    m_exit = true;
    close(m_server_fd);
}

int web_t::start()
{
    
    pthread_t tid;
    pthread_attr_t attr;
    size_t stack_size = 1024 * 1024; // Example: 1 MB stack size
    
    // Creating socket file descriptor
    if ((m_server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        printf("%s:%d: Error in cfreating socket: %d\n", __func__, __LINE__, errno);
        return -1;
    }

    if (bind(m_server_fd, (struct sockaddr *)&m_address, sizeof(m_address))<0) {
        printf("%s:%d: Error in binding: %d\n", __func__, __LINE__, errno);
        close(m_server_fd);
        return -1;
    }
    
    if (listen(m_server_fd, 10) < 0) {
        printf("%s:%d: Error in listen: %d\n", __func__, __LINE__, errno);
        return -1;
    }
    
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stack_size);
    
    if (pthread_create(&tid, &attr, run, this) != 0) {
        printf("%s:%d: Failed to start child thread\n", __func__, __LINE__);
        return -1;
    }
    
    return 0;
}

void web_t::deinit()
{
    
}

int web_t::init(const char *path)
{
    strncpy(m_head, path, strlen(path) + 1);
    
    snprintf(m_http_header, sizeof(m_http_header), "HTTP/1.1 200 Ok\r\n");
    m_exit = false;
    
    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(PORT);

    memset(m_address.sin_zero, '\0', sizeof m_address.sin_zero);
    
    return 0;
}

web_t::web_t()
{

}

web_t::~web_t()
{
    
}

