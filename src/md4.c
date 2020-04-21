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
#include "apr_md4.h"

orthrus_error_t* orthrus__alg_md4_fold(const char *seed,
                                       apr_size_t slen,
                                       const char *pw,
                                       apr_size_t pwlen,
                                       orthrus_response_t *reply)
{
  int j;
  unsigned char digest[APR_MD4_DIGESTSIZE];
  apr_md4_ctx_t md4;

  apr_md4_init(&md4);

  apr_md4_update(&md4, (unsigned char*)seed, slen);
  apr_md4_update(&md4, (unsigned char*)pw, pwlen);

  apr_md4_final(digest, &md4);
  
  for (j = 0; j < 8; j++) {
    digest[j] ^= digest[j+8];
  }


#ifndef BIGENDIAN
    /* reverse the order */
    for (j=0; j<4; ++j) {
        char tmp   = digest[j];
        digest[j]  = digest[7-j];
        digest[7-j]= tmp;
    }
#endif

  memcpy(&reply->reply, &digest[0], 8);

  return ORTHRUS_SUCCESS;
}

orthrus_error_t* orthrus__alg_md4_cycle(apr_uint64_t sequence, 
                                        orthrus_response_t *reply)
{
  int i,j;
  unsigned char digest[APR_MD4_DIGESTSIZE];
  apr_md4_ctx_t md4;

  memcpy(&digest[0], &reply->reply, 8);

#ifndef BIGENDIAN
    /* reverse the order */
    for (j=0; j<4; ++j) {
        char tmp   = digest[j];
        digest[j]  = digest[7-j];
        digest[7-j]= tmp;
    }
#endif

  for (i = 0; i < sequence; i++) {
    apr_md4_init(&md4);
    apr_md4_update(&md4, &digest[0], 8);
    apr_md4_final(digest, &md4);
    for (j = 0; j < 8; j++) {
      digest[j] ^= digest[j+8];
    }
  }

#ifndef BIGENDIAN
    /* reverse the order */
    for (j=0; j<4; ++j) {
        char tmp   = digest[j];
        digest[j]  = digest[7-j];
        digest[7-j]= tmp;
    }
#endif

  memcpy(&reply->reply, &digest[0], 8);

  return ORTHRUS_SUCCESS;
}
