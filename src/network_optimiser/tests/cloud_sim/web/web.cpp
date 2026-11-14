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
#include <cmath>
#include "web.h"
#include "em_base.h"

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
    const char *ptr;
    optimizer_event_t rsp;
    optimizer_event_type_t type;
    
    strncpy(file_name, m_head, strlen(m_head) + 1);
            
    //printf("%s:%d: action string: %s\n", __func__, __LINE__, action_string); 
    
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
                type = optimizer_event_type_get_topology;
            } else if (strncmp(tmp, "DataElements", strlen("DataElements")) == 0) {
                type = optimizer_event_type_get_de;
            } else if (strncmp(tmp, "NeighboringWiFiDiagnostic", strlen("NeighboringWiFiDiagnostic")) == 0) {
                type = optimizer_event_type_nbr_wifi_diag;
            }
            
            optimizer_event_t req(type);    
            send_message(sock, extn_type, false, device_request(&req, &rsp));
        } else {
            //send real file
            strcat(file_name, action_string);
            send_message(sock, extn_type, true, file_name);
        }
    }
}
    
namespace {
bool is_scan_uint(const cJSON *value, double maximum = 4294967295.0)
{
    return cJSON_IsNumber(value) && std::isfinite(value->valuedouble) &&
        value->valuedouble >= 0 && value->valuedouble <= maximum &&
        std::floor(value->valuedouble) == value->valuedouble;
}

bool valid_scan_request(const cJSON *request, bool full_scan)
{
    if (!cJSON_IsObject(request)) {
        return false;
    }
    const cJSON *input = cJSON_GetObjectItemCaseSensitive(request, "Input");
    if (!cJSON_IsObject(input) ||
        !is_scan_uint(cJSON_GetObjectItemCaseSensitive(input, "DwellTime")) ||
        !is_scan_uint(cJSON_GetObjectItemCaseSensitive(input, "DFSDwellTime"))) {
        return false;
    }
    const cJSON *home = cJSON_GetObjectItemCaseSensitive(input, "HomeTime");
    const cJSON *ssid = cJSON_GetObjectItemCaseSensitive(input, "SSID");
    if ((home != NULL && !is_scan_uint(home)) || (ssid != NULL && !cJSON_IsString(ssid))) {
        return false;
    }
    if (full_scan) {
        const char *band = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(request, "Band"));
        return band != NULL && (strcmp(band, "2.4GHz") == 0 ||
            strcmp(band, "5GHz") == 0 || strcmp(band, "6GHz") == 0);
    }

    const cJSON *classes = cJSON_GetObjectItemCaseSensitive(input, "OpClass");
    if (!cJSON_IsArray(classes)) {
        return false;
    }
    const cJSON *op_class;
    cJSON_ArrayForEach(op_class, classes) {
        if (!cJSON_IsObject(op_class) ||
            !is_scan_uint(cJSON_GetObjectItemCaseSensitive(op_class, "OperatingClass"), 255)) {
            return false;
        }
        const cJSON *channels = cJSON_GetObjectItemCaseSensitive(op_class, "Channel");
        if (!cJSON_IsArray(channels)) {
            return false;
        }
        const cJSON *channel;
        cJSON_ArrayForEach(channel, channels) {
            if (!cJSON_IsObject(channel) ||
                !is_scan_uint(cJSON_GetObjectItemCaseSensitive(channel, "Channel"), 255)) {
                return false;
            }
        }
    }
    return true;
}
}

void web_t::handle_post(int sock, const char *action_string, char *buffer)
{
    char *body;
    optimizer_event_t rsp;
    optimizer_event_type_t type;

    body = strstr(buffer, "\r\n\r\n");
    if (body == NULL) {
        send_message(sock, web_data_extn_type_json, false, "{\"error\":\"Invalid HTTP request\"}");
        return;
    }
    body += 4;

    if (strcmp(action_string, "/SetSSID") == 0) {
        type = optimizer_event_type_set_ssid;
    } else if (strcmp(action_string, "/FullScan") == 0) {
        type = optimizer_event_type_full_scan;
    } else if (strcmp(action_string, "/ChannelScan") == 0) {
        type = optimizer_event_type_channel_scan;
    } else {
        send_message(sock, web_data_extn_type_json, false, "{\"Status\":\"Error_Invalid_Input\"}");
        return;
    }
/*
    if (type == optimizer_event_type_full_scan || type == optimizer_event_type_channel_scan) {
        cJSON *request = cJSON_Parse(body);
        bool valid = valid_scan_request(request, type == optimizer_event_type_full_scan);
        cJSON_Delete(request);
        if (!valid) {
            printf("%s:%d: Invalid %s input\n", __func__, __LINE__, action_string);
            send_message(sock, web_data_extn_type_json, false, "{\"Status\":\"Error_Invalid_Input\"}");
            return;
        }
    }
*/

    optimizer_event_t req(type, body);
    if (req.get_data() == NULL) {
        send_message(sock, web_data_extn_type_json, false, "{\"Status\":\"Error_Other\"}");
        return;
    }
    const char *result = device_request(&req, &rsp);
    if (result == NULL) {
        send_message(sock, web_data_extn_type_json, false, "{\"Status\":\"Error_Other\"}");
    } else {
        printf("%s:%d: Result: %s\n", __func__, __LINE__, result);
        send_message(sock, web_data_extn_type_json, false, result);
    }
}

int web_t::server(int sock)
{
    char buffer[30000] = {0};
    long valread, content_length = 0, body_length;
    char *method, *action;
   
    valread = read(sock, buffer, sizeof(buffer) - 1);
    if (valread <= 0) {
        return -1;
    }
    buffer[valread] = '\0';

    if ((method = parse_method(buffer, " ")) == NULL) {  //Try to get the path which the client ask for
        return -1;
    }

    if ((action = parse(buffer, " ")) == NULL) {
        return -1;
    }
    
    if (strncmp(method, "GET", strlen("GET")) == 0) {
        handle_get(sock, action);
    } else if (strncmp(method, "POST", strlen("POST")) == 0) {
        char *content_length_header = strstr(buffer, "Content-Length:");
        char *body = strstr(buffer, "\r\n\r\n");
        if ((content_length_header == NULL) || (body == NULL) ||
            (sscanf(content_length_header, "Content-Length: %ld", &content_length) != 1) ||
            (content_length < 0)) {
            send_message(sock, web_data_extn_type_json, false, "{\"error\":\"Invalid Content-Length\"}");
            close(sock);
            return -1;
        }

        body += 4;
        body_length = valread - (body - buffer);
        if ((content_length >= static_cast<long>(sizeof(buffer))) ||
            ((body - buffer) + content_length >= static_cast<long>(sizeof(buffer)))) {
            send_message(sock, web_data_extn_type_json, false, "{\"error\":\"Request body is too large\"}");
            close(sock);
            return -1;
        }

        while (body_length < content_length) {
            long bytes_read = read(sock, buffer + valread,
                sizeof(buffer) - static_cast<size_t>(valread) - 1);
            if (bytes_read <= 0) {
                send_message(sock, web_data_extn_type_json, false, "{\"error\":\"Incomplete request body\"}");
                close(sock);
                return -1;
            }
            valread += bytes_read;
            body_length += bytes_read;
            buffer[valread] = '\0';
        }
        body[content_length] = '\0';
        handle_post(sock, action, buffer);
    }
    close(sock);

    return 0;
}

int web_t::run()
{
    int new_sock;
    int addrlen = sizeof(m_address);
  
    while (m_exit == false) {
        if ((new_sock = accept(m_server_fd, (struct sockaddr *)&m_address, (socklen_t*)&addrlen))<0) {
            printf("%s:%d: Error in accept: %d\n", __func__, __LINE__, errno);
            return -1;
        }
    
        server(new_sock);
    }
    
    return 0;
}

void web_t::stop()
{
    m_exit = true;
    close(m_server_fd);
}

int web_t::start()
{
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
    
    return run();
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
