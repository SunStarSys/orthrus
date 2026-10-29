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

/* Validators for every field that reaches us from outside: challenge
 * strings, records read back from the user database, and names handed in
 * by the caller.
 *
 * The checks are deliberately written against explicit character ranges
 * rather than the <ctype.h> predicates. Those take an int that must be
 * representable as unsigned char or EOF, and every caller here has a plain
 * char in hand, which is signed on most platforms -- passing a byte with
 * the high bit set is undefined behaviour.
 */

#include "orthrus.h"
#include "private/context.h"
#include "apr_strings.h"

static int is_alnum_ascii(char c)
{
  return (c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9');
}

/* RFC 2289 Section 6.0, "Form of Inputs":
 * The seed MUST consist of purely alphanumeric characters and MUST be of
 * one to 16 characters in length.
 *
 * Only the length was ever checked. A seed is written into the user
 * database as the third of five space-separated fields, so one containing
 * a space split into two fields and shifted everything after it along.
 */
orthrus_error_t* orthrus__validate_seed(const char *seed)
{
  apr_size_t len;
  const char *p;

  if (seed == NULL) {
    return orthrus_error_create(APR_BADARG, "no seed given");
  }

  len = strlen(seed);

  if (len < 1 || len > ORTHRUS_MAX_SEED_LEN) {
    return orthrus_error_createf(APR_BADARG, "Seed of length %"
                                 APR_SIZE_T_FMT " was given. Seed must be "
                                 "between 1 and %d characters",
                                 len, ORTHRUS_MAX_SEED_LEN);
  }

  for (p = seed; *p; p++) {
    if (!is_alnum_ascii(*p)) {
      return orthrus_error_createf(APR_BADARG, "Seed '%s' is not purely "
                                   "alphanumeric", seed);
    }
  }

  return ORTHRUS_SUCCESS;
}

/* A user name is the first of five space-separated fields, and a line
 * whose first character is '#' is a comment. Letting either through would
 * let a name forge record boundaries in the database.
 *
 * This stays deliberately permissive about everything else, because the
 * names come from the system password file and we are in no position to
 * second-guess what an administrator created.
 */
orthrus_error_t* orthrus__validate_username(const char *username)
{
  apr_size_t len;
  const char *p;

  if (username == NULL) {
    return orthrus_error_create(APR_BADARG, "no user name given");
  }

  len = strlen(username);

  if (len < 1 || len > ORTHRUS_MAX_USERNAME_LEN) {
    return orthrus_error_createf(APR_BADARG, "User name of length %"
                                 APR_SIZE_T_FMT " was given. It must be "
                                 "between 1 and %d characters",
                                 len, ORTHRUS_MAX_USERNAME_LEN);
  }

  if (*username == '#') {
    return orthrus_error_create(APR_BADARG,
                                "user name may not begin with '#'");
  }

  for (p = username; *p; p++) {
    unsigned char c = (unsigned char) *p;

    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      return orthrus_error_createf(APR_BADARG, "User name '%s' contains "
                                   "whitespace", username);
    }

    if (c < 0x20 || c == 0x7f) {
      return orthrus_error_createf(APR_BADARG, "User name '%s' contains a "
                                   "control character", username);
    }
  }

  return ORTHRUS_SUCCESS;
}

/* Parse a decimal sequence number.
 *
 * apr_strtoi64() was used for this and reports nothing: a field of "abc"
 * came back as 0, which is indistinguishable from a genuinely spent
 * sequence, and anything past 64 bits saturated silently.
 */
orthrus_error_t* orthrus__validate_sequence(const char *input,
                                            apr_uint32_t *out)
{
  apr_uint64_t v = 0;
  const char *p;
  int digits = 0;

  *out = 0;

  if (input == NULL || *input == '\0') {
    return orthrus_error_create(APR_BADARG, "no sequence number given");
  }

  for (p = input; *p; p++) {
    if (*p < '0' || *p > '9') {
      return orthrus_error_createf(APR_BADARG, "Sequence '%s' is not a "
                                   "decimal number", input);
    }

    v = (v * 10) + (apr_uint64_t)(*p - '0');

    if (++digits > 10 || v > 0xFFFFFFFFULL) {
      return orthrus_error_createf(APR_BADARG, "Sequence '%s' is out of "
                                   "range", input);
    }
  }

  *out = (apr_uint32_t) v;

  return ORTHRUS_SUCCESS;
}
