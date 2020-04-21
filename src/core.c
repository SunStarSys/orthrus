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
#include <ctype.h> /* for tolower */

/* This really really should be using ap_providers, BUT those are part of
 * httpd, not APR, lame.
 */
typedef orthrus_error_t* (*alg_fold_t)(const char *seed,
                          apr_size_t slen,
                          const char *pw,
                          apr_size_t pwlen,
                          orthrus_response_t *reply);

typedef orthrus_error_t* (*alg_cycle_t)(apr_uint64_t sequence,
                                       orthrus_response_t *reply);

typedef struct alg_impl_t {
  int id;
  const char *name;
  alg_fold_t fold;
  alg_cycle_t cycle;
} alg_impl_t;

static alg_impl_t orthrus_algs[] = {
  {ORTHRUS_ALG_MD4, "md4", orthrus__alg_md4_fold, orthrus__alg_md4_cycle},
  {ORTHRUS_ALG_MD5, "md5", orthrus__alg_md5_fold, orthrus__alg_md5_cycle},
  {ORTHRUS_ALG_SHA1, "sha1", orthrus__alg_sha1_fold, orthrus__alg_sha1_cycle},
};

orthrus_error_t* orthrus_create(apr_pool_t *pool, orthrus_t **out_ort)
{
  orthrus_t *ort;
  apr_pool_t *p;
  apr_pool_create(&p, pool);

  ort = apr_pcalloc(p, sizeof(orthrus_t));
  
  ort->pool = p;

  *out_ort = ort;

  return ORTHRUS_SUCCESS;
}

static char *strtolower(char *input)
{
  char *p = input;
  while (*p != '\0') {
    *p = tolower(*p);
    p++;
  }
  return input;
}

orthrus_error_t* orthrus_calculate(orthrus_t *ort,
                                   orthrus_response_t **out_reply,
                                   apr_uint32_t alg,
                                   apr_uint64_t sequence,
                                   const char *in_seed,
                                   const char *pw,
                                   apr_size_t pwlen,
                                   apr_pool_t *pool)
{
  int i;
  alg_impl_t *algimpl = NULL;
  orthrus_error_t* err;
  apr_size_t slen;
  char *seed;
  orthrus_response_t *reply;

  *out_reply = NULL;

  /* RFC 2289 Section 5.0:
   * All conforming implementations of both server and generators MUST support
   * MD5.  They SHOULD support SHA and MAY also support MD4.
   */

  for (i = 0; i < sizeof(orthrus_algs) / sizeof(orthrus_algs[0]); i++) {
    if (alg == orthrus_algs[i].id) {
      algimpl = &orthrus_algs[i];
      break;
    }
  }

  if (algimpl == NULL) {
    return orthrus_error_create(APR_ENOTIMPL,  "md4 and md5 are the only supported algorithms at this time.");
  }
  
  /* RFC 2289 Section 6.0, "Form of Inputs":
   * The seed MUST be case insensitive and MUST be internally converted to
   * lower case before it is processed.
   */
  seed = strtolower(apr_pstrdup(pool, in_seed));

  /* TODO: Figure out what characters are actualy used, is [a-z0-9] actually 
   * enough ? */
  /*
   * The seed MUST consist of purely alphanumeric characters and MUST be
   * of one to 16 characters in length.
   */
  slen = strlen(seed);
  if (slen < 1 || slen > 16) {
    return orthrus_error_createf(APR_BADARG, "Seed of length %"
                                 APR_SIZE_T_FMT" was given. Seed must be "
                                 "between 1 and 16 characters", slen);
  }

  
  reply = apr_pcalloc(pool, sizeof(orthrus_response_t));

  reply->pool = pool;
  
  err = algimpl->fold(seed, slen, pw, pwlen, reply);

  if (err) {
    return err;
  }

  err = algimpl->cycle(sequence, reply);
  if (err) {
    return err;
  }

  orthrus__format_hex(reply, pool);
  orthrus__format_words(reply, pool);
  
  *out_reply = reply;

  return ORTHRUS_SUCCESS;
}


