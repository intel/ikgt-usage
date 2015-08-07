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

#ifndef _STRING_H_
#define _STRING_H_

#include "common_types.h"

typedef uint64_t size_t;


int CDECL mon_sprintf_s(char *buffer, size_t size_of_buffer, const char *format, ...);

void *CDECL mon_memset(void *dest, int filler, size_t count);

char *CDECL mon_strcpy_s(char *dst, size_t dst_length, const char *src);

#endif /* _STRING_H_ */
