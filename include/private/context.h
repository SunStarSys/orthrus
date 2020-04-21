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

#ifndef _ORTHRUS_PRIVATE_CONTEXT_H_
#define _ORTHRUS_PRIVATE_CONTEXT_H_

#include "orthrus.h"
#include <apr_file_io.h>

#ifdef __cplusplus
extern "C" {
#endif

struct orthrus_t {
  apr_pool_t *pool;
  apr_file_t *userdb;
  apr_file_t *lock;
  const char *path;
  const char *lockpath;
};


orthrus_error_t* orthrus__alg_md4_fold(const char *seed,
                                       apr_size_t slen,
                                       const char *pw,
                                       apr_size_t pwlen,
                                       orthrus_response_t *reply);

orthrus_error_t* orthrus__alg_md4_cycle(apr_uint64_t sequence, 
                                        orthrus_response_t *reply);
  
orthrus_error_t* orthrus__alg_md5_fold(const char *seed,
                                       apr_size_t slen,
                                       const char *pw,
                                       apr_size_t pwlen,
                                       orthrus_response_t *reply);

orthrus_error_t* orthrus__alg_md5_cycle(apr_uint64_t sequence, 
                                        orthrus_response_t *reply);

orthrus_error_t* orthrus__alg_sha1_fold(const char *seed,
                                       apr_size_t slen,
                                       const char *pw,
                                       apr_size_t pwlen,
                                       orthrus_response_t *reply);

orthrus_error_t* orthrus__alg_sha1_cycle(apr_uint64_t sequence, 
                                        orthrus_response_t *reply);

void orthrus__format_hex(orthrus_response_t *reply, apr_pool_t *pool);
void orthrus__decode_hex(const char *input, apr_uint64_t *output);
void orthrus__format_words(orthrus_response_t *reply, apr_pool_t *pool);
orthrus_error_t* orthrus__decode_words(const char *words, apr_uint64_t *out);

struct orthrus_response_t {
  apr_pool_t *pool;
  apr_uint64_t reply;
  const char hex[(8 * 2) + 4 + 1];
  const char *words;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
