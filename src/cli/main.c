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
#include "em_base.h"
#include <readline/readline.h>
#include <readline/history.h>
#include "em_cli_apis.h"

const char *prompt = "<<OneWifiMeshCli>>: ";


int editor(const char *args)
{
	em_long_string_t cmd;

	snprintf(cmd, sizeof(em_long_string_t), "vi %s", args);
    system(cmd);

	return 0;
}

int main(int argc, const char *argv[])
{
   	char *line = NULL;
    em_status_string_t output;

	init(editor);

    while(1) {
        line = readline(prompt);
        if (line == NULL || strcmp(line, "exit") == 0) {
            free(line);
            break;
        }

        if (strcmp(line, "history") == 0) {
            HIST_ENTRY **hist_list = history_list();
            if (hist_list) {
                for (int i = 0; hist_list[i]; i++) {
                    printf("%d. %s\n", i + 1, hist_list[i]->line);
                }
            }
        } else {
            if (*line) {
                add_history(line);
            }

            printf("%s\n", exec(line, strlen(line), output));
        }

        free(line);
    }

    return 0;
}   
