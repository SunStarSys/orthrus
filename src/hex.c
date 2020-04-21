/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "orthrus.h"
#include "private/context.h"
#include "apr_strings.h"
#include <ctype.h>

/* inverse of APR_UINT64_T_HEX_FMT */
void orthrus__decode_hex(const char *input, apr_uint64_t *output) {

  *output = 0;
  const char *p = input;
  apr_uint64_t v = 0;

  while (*p) {
    char ch = *p;
    if (ch >= '0' && ch <= '9') {
      v = (v << 4) + (ch  - '0');
    }
    else if (ch >= 'A' && ch <= 'F') {
      v = (v << 4) + (ch - 'A' + 10);
    }
    else if (ch >= 'a' && ch <= 'f') {
      v = (v << 4) + (ch - 'a' + 10);
    }
    p++;
  }

  *output = v;
}

void orthrus__format_hex(orthrus_response_t *reply, apr_pool_t *pool)
{
  int i;
  char *r = (char *)&reply->hex[0];
  char s[(8 * 2) + 1];

  apr_snprintf(s, sizeof s, "%" APR_UINT64_T_HEX_FMT, reply->reply);

  for (i = 0; i < 16; ++i) {
      if (islower(s[i]))
          s[i] = toupper(s[i]);
  }
  for (i = 0; i < 13; i += 4) {
      *r++ = s[i];
      *r++ = s[i+1];
      *r++ = s[i+2];
      *r++ = s[i+3];
      *r++ = ' ';
  }
  r[-1] = 0;
}

void orthrus_response_format_hex(orthrus_response_t *reply, const char **output)
{
  *output = reply->hex;
}



