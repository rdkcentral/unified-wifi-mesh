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
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "assert.h"
#include "de_reader.h"

cJSON *de_reader_t::get_object_item(const char *fmt, ...)
{
    va_list args;
    unsigned int pos;
    cJSON *obj = m_obj, *arr;
    em_long_string_t path = {0};
    char *ptr = path, *tmp = path;
   
    va_start(args, fmt);
    vsprintf(path, fmt, args);
    va_end(args);
 
    if (path[0] == ' ') {
        return NULL;
    }

    while (ptr = strchr(tmp, '.')) {
        if (*(ptr + 1) == '{') {
            *ptr = 0;
            arr = cJSON_GetObjectItem(obj, tmp);
            tmp = strchr(ptr + 1, '}');
            *tmp = 0; pos = atoi(ptr + 2);
            obj = cJSON_GetArrayItem(arr, pos); 
            tmp++; 
            if ((tmp != NULL) && (*tmp == '.')) {
                tmp++;
            } else {
                return obj;
            }
        } else {
            *ptr = 0;
            obj = cJSON_GetObjectItem(obj, tmp);
            ptr++; tmp = ptr;
        }
    }

    return cJSON_GetObjectItem(obj, tmp);    
}

void de_reader_t::update_network(de_network_t& net)
{
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network")) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    } 

    elem = cJSON_GetObjectItem(obj, "ID");
    str = cJSON_GetStringValue(elem);
    strncpy(net.m_id, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "ControllerID");
    str = cJSON_GetStringValue(elem);
    strncpy(net.m_controller_id, str, strlen(str) + 1);
}

unsigned int de_reader_t::get_num_services()
{
    cJSON *arr;
    
    if ((arr = get_object_item("wfa-dataelements:Network.X_RDK_Services")) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return 0;
    } 

    return cJSON_GetArraySize(arr);
}

void de_reader_t::update_service(de_service_t& svc, unsigned int pos)
{
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.X_RDK_Services.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "Type");
    svc.m_type = (service_type_t)cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(obj, "Operator");
    str = cJSON_GetStringValue(elem);
    strncpy(svc.m_operator_name, str, strlen(str) + 1);
     
    elem = cJSON_GetObjectItem(obj, "URL");
    str = cJSON_GetStringValue(elem);
    strncpy(svc.m_url, str, strlen(str) + 1);
}

unsigned int de_reader_t::get_num_devices()
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList")) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return 0;
    }

    return cJSON_GetArraySize(arr);
}

void de_reader_t::update_device(de_device_t& dev, unsigned int pos)
{
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "ID");
    str = cJSON_GetStringValue(elem);
    strncpy(dev.m_id, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "Manufacturer");
    str = cJSON_GetStringValue(elem);
    strncpy(dev.m_manufacturer, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "ManufacturerModel");
    str = cJSON_GetStringValue(elem);
    strncpy(dev.m_model, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "SerialNumber");
    str = cJSON_GetStringValue(elem);
    strncpy(dev.m_serial, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "SoftwareVersion");
    str = cJSON_GetStringValue(elem);
    strncpy(dev.m_version, str, strlen(str) + 1);

}

unsigned int de_reader_t::get_num_radios(unsigned int pos)
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList", pos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return NULL;
    }

    return cJSON_GetArraySize(arr);;
}

void de_reader_t::update_radio(de_radio_t& radio, unsigned int dpos, unsigned int rpos)
{
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "ID");
    str = cJSON_GetStringValue(elem);
    strncpy(radio.m_id, str, strlen(str) + 1);
    
    elem = cJSON_GetObjectItem(obj, "Enabled");
    radio.m_enabled = cJSON_IsTrue(elem);
}


bool de_reader_t::has_modified()
{
    int fd;
    struct stat info;
    
    if ((fd = open(m_name, O_RDONLY)) == -1) {
        printf("%s:%d: Could not open data elements file\n", __func__, __LINE__);
        return false;
    }

    if (fstat(fd, &info) != 0) {
        printf("%s:%d: Could not get size of data elements file\n", __func__, __LINE__);
        close(fd);
        return false;
    }

    if (m_info.st_mtime != info.st_mtime) {
        memcpy(&m_info, &info, sizeof(struct stat));
        close(fd);
        return true;
    }

    close(fd);
       
    return false;
}

int de_reader_t::init()
{
    int fd;
    char *buff;

    if ((fd = open(m_name, O_RDONLY)) == -1) {
        printf("%s:%d: Could not open data elements file\n", __func__, __LINE__);
        return -1;
    }

    if (fstat(fd, &m_info) != 0) {
        printf("%s:%d: Could not get size of data elements file\n", __func__, __LINE__);
        close(fd);
        return -1;
    }
        
       
    buff = (char *)malloc(m_info.st_size + 1);

    if (read(fd, buff, m_info.st_size) <= 0) {
        free(buff);
        close(fd);
        printf("%s:%d: Failed to read data elments file\n", __func__, __LINE__);
        return -1;
    }
    
    if ((m_obj = cJSON_Parse(buff)) == NULL) {
        free(buff);
        close(fd);
        printf("%s:%d: Failed to parse data elments file\n", __func__, __LINE__);
        return -1;
    }

    free(buff);
    close(fd);

    return 0;
}

void de_reader_t::deinit()
{
    cJSON_Delete(m_obj);
}

de_reader_t::de_reader_t(const char *name)
{
    memset(m_name, 0, sizeof(em_long_string_t));
    strncpy(m_name, name, strlen(name));
}

de_reader_t::~de_reader_t()
{

}
