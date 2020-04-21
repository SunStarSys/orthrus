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

#ifndef _ORTHRUS_H_
#define _ORTHRUS_H_

#include "apr.h"
#include "orthrus_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque Structure repersenting an Orthrus Context */
typedef struct orthrus_t orthrus_t;

/* Opaque Structure repersenting an OTP Response */
typedef struct orthrus_response_t orthrus_response_t;

#define ORTHRUS_ALG_MD4 (0)
#define ORTHRUS_ALG_MD5 (1)
#define ORTHRUS_ALG_SHA1 (2)

orthrus_error_t* orthrus_create(apr_pool_t *pool, orthrus_t **ort);

orthrus_error_t* orthrus_calculate(orthrus_t *ort,
                                   orthrus_response_t **reply,
                                   apr_uint32_t alg,
                                   apr_uint64_t sequence,
                                   const char *seed,
                                   const char *pw,
                                   apr_size_t pwlen,
                                   apr_pool_t *pool);

void orthrus_response_format_hex(orthrus_response_t *reply,
                                 const char **output);

void orthrus_response_format_words(orthrus_response_t *reply,
                                   const char **output);

  
/* User DB Interfaces. */
orthrus_error_t* orthrus_userdb_open(orthrus_t *ort, const char *path);
orthrus_error_t* orthrus_userdb_close(orthrus_t *ort);

orthrus_error_t* orthrus_userdb_get_challenge(orthrus_t *ort,
                                              const char *username,
                                              const char **challenge,
                                              apr_pool_t *pool);

orthrus_error_t* orthrus_userdb_verify(orthrus_t *ort,
                                       const char *username,
                                       const char *challenge,
                                       const char *reply);
orthrus_error_t* orthrus_userdb_save(orthrus_t *ort,
                                     const char *username,
                                     const char *challenge,
                                     const char *reply);
  
#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
