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

#ifndef EM_CMD_BEACON_REPORT_H
#define EM_CMD_BEACON_REPORT_H

#include "em_cmd.h"

class em_cmd_beacon_report_t : public em_cmd_t {

private:
	time_t m_beacon_query_tx_time = 0;

public:    
	bool supports_retry_state() const override { return true; }
	time_t get_query_tx_time() const override { return m_beacon_query_tx_time; }
	void set_query_tx_time(time_t tx_time) override { m_beacon_query_tx_time = tx_time; }
	void clear_query_tx_time() override { m_beacon_query_tx_time = 0; }

	/**!
	 * @brief 
	 *
	 * This function handles the beacon report command.
	 *
	 * @param[in] param The command parameters for the beacon report.
	 * @param[in,out] dm The easy mesh data structure to be updated.
	 *
	 * @returns em_cmd_beacon_report_t
	 *
	 * @note Ensure that the dm structure is properly initialized before calling this function.
	 */
	em_cmd_beacon_report_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif
