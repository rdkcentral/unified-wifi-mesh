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

    elem = cJSON_GetObjectItem(obj, "Utilization");
    radio.m_util = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "Noise");
    radio.m_noise = static_cast<int>(cJSON_GetNumberValue(elem));
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
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList.{%d}", dpos, rpos, bpos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "BSSID");
    str = cJSON_GetStringValue(elem);
    strncpy(bss.m_bssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(bss.m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "Enabled");
    bss.m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(obj, "TransmittedBSSID");
    bss.m_broadcast = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(obj, "FronthaulUse");
    bss.m_fronthaul = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(obj, "BackhaulUse");
    bss.m_backhaul = cJSON_IsTrue(elem);

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
    cJSON *obj, *elem;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.CurrentOperatingClasses.{%d}", dpos, rpos, opos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "Class");
    curr_op_class.m_class = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "TxPower");
    curr_op_class.m_tx_power = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "Channel");
    curr_op_class.m_channel = static_cast<unsigned int>(cJSON_GetNumberValue(elem));
}

void de_reader_t::update_cap(de_cap_t& cap, unsigned int dpos, unsigned int rpos)
{
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.Capabilities", dpos, rpos)) == NULL) {
        printf("%s:%d: Could not read capabilities object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "NumberOfOpClass");
    cap.m_num_op_class = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "HTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(cap.m_ht_cap, sizeof(cap.m_ht_cap), "%s", (str != NULL) ? str : "");
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

    elem = cJSON_GetObjectItem(obj, "Class");
    op_class.m_class = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "MaxTxPower");
    op_class.m_max_tx_power = static_cast<int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "NumberOfNonOperChan");
    op_class.m_num_non_oper_chan = static_cast<unsigned int>(cJSON_GetNumberValue(elem));
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
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.DeviceList.{%d}.RadioList.{%d}.BSSList.{%d}.STAList.{%d}", dpos, rpos, bpos, spos)) == NULL) {
        printf("%s:%d: Could not read devices object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "MACAddress");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_mac, sizeof(sta.m_mac), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(obj, "SignalStrength");
    sta.m_rssi = static_cast<int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "LastDataUplinkRate");
    sta.m_ul_rate = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "LastDataDownlinkRate");
    sta.m_dl_rate = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "RetransCount");
    sta.m_retrans = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "PacketsReceived");
    sta.m_pkts_rx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "PacketsSent");
    sta.m_pkts_tx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "BytesReceived");
    sta.m_bytes_rx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "BytesSent");
    sta.m_bytes_tx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(obj, "ClientCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_cap, sizeof(sta.m_cap), "%s", (str != NULL) ? str : "");

    //elem = cJSON_GetObjectItem(obj, "WiFi6Capabilities");
    //str = cJSON_GetStringValue(elem);
    //strncpy(sta.m_wifi6_cap, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "HTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_ht_cap, sizeof(sta.m_ht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(obj, "VHTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_vht_cap, sizeof(sta.m_vht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(obj, "HECapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_he_cap, sizeof(sta.m_he_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(obj, "SecurityAssociation");
    str = cJSON_GetStringValue(elem);
    snprintf(sta.m_sec_assoc, sizeof(sta.m_sec_assoc), "%s", (str != NULL) ? str : "");

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
    cJSON *obj, *elem;
    const char *str;

    if ((obj = get_object_item("wfa-dataelements:Network.NetworkSSIDList.{%d}", pos)) == NULL) {
        printf("%s:%d: Could not read network object from json\n", __func__, __LINE__);
        return;
    }

    elem = cJSON_GetObjectItem(obj, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "Enable");
    net_ssid.m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(obj, "AdvertisementEnabled");
    net_ssid.m_advertisement = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(obj, "MFPConfig");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_mfp_config, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(obj, "MobilityDomain");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_mob_domain, str, strlen(str) + 1);
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
