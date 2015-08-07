/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef _LOG_H_
#define _LOG_H_

void log_event(char *log_msg, uint64_t cpu_id);

void start_log(ikgt_event_info_t *event_info, uint64_t log_addr);

void stop_log(ikgt_event_info_t *event_info);

#endif /* _LOG_H_ */
