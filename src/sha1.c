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

#include <stdio.h>
#include "orthrus.h"
#include "private/context.h"
#include "apr_sha1.h"

orthrus_error_t* orthrus__alg_sha1_fold(const char *seed,
                                       apr_size_t slen,
                                       const char *pw,
                                       apr_size_t pwlen,
                                       orthrus_response_t *reply)
{
  apr_uint32_t digest[5];
  apr_sha1_ctx_t sha1;
  int i;
  unsigned char* bits = (unsigned char*)digest;

  apr_sha1_init(&sha1);

  apr_sha1_update_binary(&sha1, (unsigned char*)seed, slen);
  apr_sha1_update_binary(&sha1, (unsigned char*)pw, pwlen);

  apr_sha1_final((unsigned char*)&digest[0], &sha1);
  
    /* reverse the order */
    for (i=0; i<10; ++i) {
        char tmp = bits[i];
        bits[i]  = bits[19-i];
        bits[19-i]= tmp;
    }

  digest[0] ^= digest[2];
  digest[0] ^= digest[4];
  digest[1] ^= digest[3];
  
#ifndef BIGENDIAN
    /* reverse the order */
    for (i=0; i<4; ++i) {
        char tmp = bits[i];
        bits[i]  = bits[7-i];
        bits[7-i]= tmp;
    }
#endif

  memcpy(&reply->reply, &digest[0], 8);

  return ORTHRUS_SUCCESS;
}

orthrus_error_t* orthrus__alg_sha1_cycle(apr_uint64_t sequence, 
                                        orthrus_response_t *reply)
{
  int j;
  apr_uint32_t digest[5];
  apr_sha1_ctx_t sha1;
  int i;
  unsigned char* bits = (unsigned char*)digest;
  
  apr_sha1_init(&sha1);


  memcpy(&digest[0], &reply->reply, 8);

#ifndef BIGENDIAN
    /* reverse the order */
    for (i=0; i<4; ++i) {
        char tmp = bits[i];
        bits[i]  = bits[7-i];
        bits[7-i]= tmp;
    }
#endif

  for (j = 0; j < sequence; j++) {
    apr_sha1_init(&sha1);
    apr_sha1_update_binary(&sha1, (unsigned char*)&digest[0], 8);
    apr_sha1_final((unsigned char*)&digest[0], &sha1);
    /* reverse the order */
    for (i=0; i<10; ++i) {
        char tmp = bits[i];
        bits[i]  = bits[19-i];
        bits[19-i]= tmp;
    }
    digest[0] ^= digest[2];
    digest[1] ^= digest[3];
    digest[0] ^= digest[4];
  }

#ifndef BIGENDIAN
    /* reverse the order */
    for (i=0; i<4; ++i) {
        char tmp = bits[i];
        bits[i]  = bits[7-i];
        bits[7-i]= tmp;
    }
#endif

  memcpy(&reply->reply, &digest[0], 8);
  
  return ORTHRUS_SUCCESS;
}
