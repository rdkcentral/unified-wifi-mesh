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
#include "bus.h"
#include "bus_common.h"
#include "tr_181.h"

typedef enum{
	CONTROLLERID,
	COLOCATEDAGENTID,
	SETSSID
}test_tr;

void print_options()
{
	printf("\n ---------------------------------------------------");
	printf("\n Test TR-Param");
	printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID:%d",CONTROLLERID);
	printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID:%d",COLOCATEDAGENTID);
	printf("\n ---------------------------------------------------");
	printf("\n");
}
int main()
{
	wifi_bus_desc_t *desc;
	bus_handle_t m_bus_hdl;
	raw_data_t data;
	int num_retry = 0;
	bus_error_t bus_error_val;
	int rc = bus_error_success;
	char service_name[] = "Test_TR181";
	int input = 0;
	bus_init(&m_bus_hdl);
	if((desc = get_bus_descriptor()) == NULL) {
		printf("%s:%d descriptor is null\n", __func__, __LINE__);
	}
	if (desc->bus_open_fn(&m_bus_hdl, service_name) != 0) {
		printf("%s:%d bus open failed\n",__func__, __LINE__);
		return 0;
	}
	printf("%s:%d he_bus open success\n", __func__, __LINE__);
	while(1) {
		print_options();
		printf("\n Enter number to test: ");
		scanf("%d", &input);
		memset(&data, 0, sizeof(raw_data_t));
		printf("%s:%d input=%d\n",__func__, __LINE__, input);
		if (input == CONTROLLERID) {
			if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID, &data)) != bus_error_success ) {
				printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
			}
			printf("\n%s:%d recv data: CONTROLLERID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
			get_bus_descriptor()->bus_data_free_fn(&data);
		} else if (input == COLOCATEDAGENTID) { 
			if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID, &data)) != bus_error_success ) {
				printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
			}
			printf("\n%s:%d recv data:COLOCATEDAGENTID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
			get_bus_descriptor()->bus_data_free_fn(&data);
		}
	}
	return 0;
}
