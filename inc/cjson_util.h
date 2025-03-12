/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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

 #ifndef __CJSON_UTIL__
 #define __CJSON_UTIL__ 

 #include "cjson/cJSON.h"

 namespace cjson_utils {

    /**
     * @brief Get the size, in bytes, of a cJSON JSON string.
     * 
     * @param json The JSON instance to get the size of.
     * @return size_t The size / length of the JSON instance, in bytes.
     */
    static inline size_t get_cjson_blob_size(const cJSON *const json) {
        size_t len = 0UL;
        if (json != NULL) {
            char *s = cJSON_Print(json);
            if (s) {
                len = strlen(s);
                free(s);
            }
        }
        return len;
    }
 }


 #endif // __CJSON_UTIL__

