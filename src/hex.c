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

/* Inverse of APR_UINT64_T_HEX_FMT.
 *
 * Whitespace is skipped, since RFC 2289 prints hexadecimal responses in
 * groups of four digits. Anything else is an error.
 *
 * This used to ignore every unrecognised character and had no way to fail,
 * so "hello" and "" both decoded to 0 and a 40-digit string silently
 * overflowed into a plausible value. A caller could not tell a malformed
 * one-time password from a real one, and verification then went on to hash
 * whatever fell out.
 */
orthrus_error_t* orthrus__decode_hex(const char *input, apr_uint64_t *output)
{
  const char *p;
  apr_uint64_t v = 0;
  int digits = 0;

  *output = 0;

  if (input == NULL) {
    return orthrus_error_create(APR_BADARG, "no response given");
  }

  for (p = input; *p; p++) {
    char ch = *p;
    int nibble;

    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
      continue;
    }

    if (ch >= '0' && ch <= '9') {
      nibble = ch - '0';
    }
    else if (ch >= 'A' && ch <= 'F') {
      nibble = ch - 'A' + 10;
    }
    else if (ch >= 'a' && ch <= 'f') {
      nibble = ch - 'a' + 10;
    }
    else {
      return orthrus_error_create(APR_BADARG,
                                  "response is not a hexadecimal number");
    }

    /* A 64-bit response is 16 digits; more than that would shift the
     * leading ones straight out of the value. */
    if (++digits > 16) {
      return orthrus_error_create(APR_BADARG,
                                  "hexadecimal response is longer than 64 bits");
    }

    v = (v << 4) + nibble;
  }

  if (digits == 0) {
    return orthrus_error_create(APR_BADARG,
                                "response contains no hexadecimal digits");
  }

  *output = v;

  return ORTHRUS_SUCCESS;
}

void orthrus__format_hex(orthrus_response_t *reply, apr_pool_t *pool)
{
  int i;
  char *r = (char *)&reply->hex[0];
  char s[(8 * 2) + 1];

  /* The 016 is load-bearing: APR_UINT64_T_HEX_FMT carries no width, so a
   * reply with a zero top nibble -- about one in sixteen -- formatted
   * shorter than 16 digits. The loops below always read 16, so they ran past
   * the terminator into uninitialised stack and emitted a malformed OTP
   * (0x0130c932d518cd2a printed as "130C 932D 518C D2A"). */
  apr_snprintf(s, sizeof s, "%016" APR_UINT64_T_HEX_FMT, reply->reply);

  for (i = 0; i < 16; ++i) {
      if (islower((unsigned char)s[i]))
          s[i] = toupper((unsigned char)s[i]);
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



