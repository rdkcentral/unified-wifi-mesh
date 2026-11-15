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
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network")) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    } 

    net.deserialize(obj);
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
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.X_RDK_Services.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    }

    svc.deserialize(obj);
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
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    dev.deserialize(obj);

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
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    radio.deserialize(obj);
}

unsigned int de_reader_t::get_num_bsss(unsigned int dpos, unsigned int rpos)
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return NULL;
    }

    return cJSON_GetArraySize(arr);;
}

void de_reader_t::update_bss(de_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList.{%d}", dpos, rpos, bpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    bss.deserialize(obj)

}

unsigned int de_reader_t::get_num_curr_op_classes(unsigned int dpos, unsigned int rpos)
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.CurrentOperatingClasses", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return 0;
    }

    return cJSON_GetArraySize(arr);
}

void de_reader_t::update_curr_op_class(de_curr_op_class_t& curr_op_class, unsigned int dpos, unsigned int rpos, unsigned int opos)
{
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.CurrentOperatingClasses.{%d}", dpos, rpos, opos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    curr_op_class.deserialize(obj);
}

void de_reader_t::update_cap(de_cap_t& cap, unsigned int dpos, unsigned int rpos)
{
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.Capabilities", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read capabilities object from json\n", __func__, __LINE__);
        return;
    }

    cap.deserialize(obj);
}

unsigned int de_reader_t::get_num_op_classes(unsigned int dpos, unsigned int rpos)
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.Capabilities.OperatingClasses", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read operating classes object from json\n", __func__, __LINE__);
        return 0;
    }

    return cJSON_GetArraySize(arr);
}

void de_reader_t::update_op_class(de_op_class_t& op_class, unsigned int dpos, unsigned int rpos, unsigned int opos)
{
    cJSON *obj, *elem;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.Capabilities.OperatingClasses.{%d}", dpos, rpos, opos)) == NULL) {
        printf("%s:%d: Could not read operating class object from json\n", __func__, __LINE__);
        return;
    }

    op_class.deserialize(obj);
}

unsigned int de_reader_t::get_num_stas(unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList.{%d}.STAList", dpos, rpos, bpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return NULL;
    }

    return cJSON_GetArraySize(arr);;
}

void de_reader_t::update_sta(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos)
{
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList.{%d}.STAList.{%d}", dpos, rpos, bpos, spos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    sta.deserialize(obj);

}

unsigned int de_reader_t::get_num_net_ssids()
{
    cJSON *arr;

    if ((arr = get_object_item("wfa-dataelements:Network.NetworkSSIDList")) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return 0;
    }

    return cJSON_GetArraySize(arr);
}

void de_reader_t::update_net_ssid(de_net_ssid_t& net_ssid, unsigned int pos)
{
    cJSON *obj;

    if ((obj = get_object_item("wfa-dataelements:Network.NetworkSSIDList.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    }

    net_ssid.deserialize(obj);
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
    ssize_t bytes_read;

    if ((fd = open(m_name, O_RDONLY)) == -1) {
        printf("%s:%d: Could not open data elements file\n", __func__, __LINE__);
        return -1;
    }

    if (fstat(fd, &m_info) != 0) {
        printf("%s:%d: Could not get size of data elements file\n", __func__, __LINE__);
        close(fd);
        return -1;
    }
        
       
    buff = (char *)malloc(static_cast<size_t>(m_info.st_size) + 1);
    if (buff == NULL) {
        close(fd);
        printf("%s:%d: Failed to allocate data elements buffer\n", __func__, __LINE__);
        return -1;
    }

    bytes_read = read(fd, buff, static_cast<size_t>(m_info.st_size));
    if (bytes_read != m_info.st_size) {
        free(buff);
        close(fd);
        printf("%s:%d: Failed to read complete data elements file\n", __func__, __LINE__);
        return -1;
    }

    buff[bytes_read] = '\0';
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
    m_obj = NULL;
}

de_reader_t::de_reader_t(const char *name)
{
    m_obj = NULL;
    memset(&m_info, 0, sizeof(m_info));
    memset(m_name, 0, sizeof(em_long_string_t));
    if (name != NULL) {
        snprintf(m_name, sizeof(m_name), "%s", name);
    }
}

de_reader_t::~de_reader_t()
{

}
