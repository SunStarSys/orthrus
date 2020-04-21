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
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_time.h"

#define ORT_USERDB_MAX_LINE_LEN 1024

orthrus_error_t* orthrus_userdb_close(orthrus_t *ort)
{

  if (ort->userdb) {
    apr_file_close(ort->lock);
    apr_file_close(ort->userdb);
    ort->userdb = NULL;
    ort->lock = NULL;
  }

  return ORTHRUS_SUCCESS;
}

orthrus_error_t* orthrus_userdb_open(orthrus_t *ort, const char *path)
{
  apr_status_t rv;

  if (ort->userdb) {
    orthrus_userdb_close(ort);
  }

  ort->path = apr_pstrdup(ort->pool, path);
  ort->lockpath = apr_pstrcat(ort->pool, path, ".lock", NULL);

  rv = apr_file_open(&ort->lock, ort->lockpath,
                     APR_READ|APR_WRITE|APR_CREATE|APR_BINARY,
                     APR_UREAD|APR_UWRITE, ort->pool);
  if (rv) {
      return orthrus_error_createf(rv, "Unable to open %s", ort->lockpath);
  }

  rv = apr_file_lock(ort->lock, APR_FLOCK_EXCLUSIVE);
  if (rv) {
      return orthrus_error_createf(rv, "Unable to lock %s", ort->lockpath);
  }

  rv = apr_file_open(&ort->userdb, path, APR_READ|APR_WRITE|APR_CREATE|APR_BINARY,
                     APR_UREAD|APR_UWRITE, ort->pool);
  if (rv) {
    return orthrus_error_createf(rv, "Unable to open %s", ort->path);
  }

  return ORTHRUS_SUCCESS;
}

typedef struct orthrus_challenge_t {
  apr_uint32_t sequence;
  const char *seed;
} orthrus_challenge_t;

typedef struct orthrus_user_t {
  const char *username;
  orthrus_challenge_t ch;
  const char *lastreply;
} orthrus_user_t;

static orthrus_error_t* userdb_get_user(orthrus_t *ort,
                                        const char *username,
                                        orthrus_user_t **out_user)
{
  char line[ORT_USERDB_MAX_LINE_LEN];
  int lineno = 0;
  orthrus_user_t *user = NULL;
  apr_off_t start = 0;
  apr_status_t rv;

  rv = apr_file_seek(ort->userdb, APR_SET, &start);
  if (rv) {
      return orthrus_error_create(rv, "can't seek to start of dbfile");
  }
  while (apr_file_gets(line, sizeof(line), ort->userdb) == APR_SUCCESS) {
    lineno++;
    char *strtok_state;
    char *v;
    if (*line == '#' || apr_isspace(*line)) {
      continue;
    }
    
    /**
     * UserDB Format:
     * $username $sequence $seed $lastreply $date_of_last_use
     * foobar 0400 mi3444  asdgfhasgdfjkh  Mar 04,2009 21:45:09
     *
     * We don't parse the date, just the first 4 fields.
     */
    v = apr_strtok(line, " ", &strtok_state);
    if (!v) {
      continue;
    }
    
    if (strcmp(v, username) != 0) {
      continue;
    }

    user = apr_pcalloc(ort->pool, sizeof(orthrus_user_t));
    user->username = apr_pstrdup(ort->pool, v);

    v = apr_strtok(NULL, " ", &strtok_state);
    if (!v) {
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d", lineno);
    }

    user->ch.sequence = apr_strtoi64(v, NULL, 10);

    v = apr_strtok(NULL, " ", &strtok_state);
    if (!v) {
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d", lineno);
    }

    user->ch.seed = apr_pstrdup(ort->pool, v);

    v = apr_strtok(NULL, " ", &strtok_state);
    if (!v) {
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d", lineno);
    }
    
    user->lastreply = apr_pstrdup(ort->pool, v);

    break;
  }

  if (user) {
    *out_user = user;
    return ORTHRUS_SUCCESS;
  }

  return orthrus_error_create(APR_NOTFOUND, "user not found");
}

orthrus_error_t* orthrus_userdb_get_challenge(orthrus_t *ort,
                                              const char *username,
                                              const char **challenge,
                                              apr_pool_t *pool)
{
  orthrus_error_t* err;
  orthrus_user_t *user;

  err = userdb_get_user(ort, username, &user);
  if (err) {
    return err;
  }

  /* TODO: Configurable algorithms */
  *challenge = apr_psprintf(pool, "otp-md5 %u %s", user->ch.sequence - 1,  user->ch.seed);
  
  return ORTHRUS_SUCCESS;
}

static orthrus_error_t* decode_challenge(orthrus_t *ort,
                                         const char *challenge,
                                         orthrus_challenge_t *ch)
{
  char *strtok_state;
  char *v;
  char *p = apr_pstrdup(ort->pool, challenge);
  
  /* len("otp-md5 1 a") = 11 */
  if (strlen(p) < 11) {
    return orthrus_error_create(APR_EGENERAL, "challenge string is too small.");
  }
  
  p += 4;

  if (strncmp("md5 ", p, 4) != 0) {
    return orthrus_error_create(APR_ENOTIMPL, "only md5 verification is supported.");
  }
  
  p += 4;
  
  v = apr_strtok(p, " ", &strtok_state);
  
  if (!v) {
    return orthrus_error_create(APR_EGENERAL, "invalid challenge string when looking for sequence.");
  }
  
  ch->sequence = apr_strtoi64(v, NULL, 10);
  
  v = apr_strtok(NULL, " ", &strtok_state);
  if (!v) {
    return orthrus_error_create(APR_EGENERAL,
                                "invalid challenge string when looking for seed.");
  }
  
  ch->seed = apr_pstrdup(ort->pool, v);

  return ORTHRUS_SUCCESS;
}

static orthrus_error_t* decode_reply(orthrus_t *ort,
                                    const char *reply,
                                    orthrus_response_t **out_resp)
{
  orthrus_response_t *resp;
  /* TODO: Support Six word dictionary decoding.
   *  (note, its just a SHOULD from the RFC) */
  
  /* RFC 2289 Section 6.0, "Form of Output":
   * If a six-word encoded one-time password is valid, it is accepted.  
   * Otherwise, if the one-time password can be interpreted as hexadecimal, and 
   * with that decoding it is valid, then it is accepted.*/
  resp = apr_pcalloc(ort->pool, sizeof(orthrus_response_t));
  resp->pool = ort->pool;

  if (orthrus__decode_words(reply, &resp->reply) != ORTHRUS_SUCCESS)
      orthrus__decode_hex(reply, &resp->reply);

  *out_resp =  resp;

  return ORTHRUS_SUCCESS;
}

static
orthrus_error_t* update_db(orthrus_t *ort, orthrus_user_t *user, apr_uint64_t reply)
{
    char line[ORT_USERDB_MAX_LINE_LEN], *tmpfilename;
    int found = 0;
    apr_status_t rv;
    apr_file_t *tmpfile;
    apr_off_t start = 0;

    tmpfilename = apr_pstrcat(ort->pool, ort->path, ".tmp", NULL);
    rv = apr_file_open(&tmpfile, tmpfilename, APR_READ|APR_WRITE|APR_CREATE|APR_BINARY,
                     APR_UREAD|APR_UWRITE, ort->pool);
    if (rv) {
        return orthrus_error_create(rv, "can't open temporary dbfile");
    }

    rv = apr_file_seek(ort->userdb, APR_SET, &start);
    if (rv) {
        return orthrus_error_create(rv, "can't seek to start of dbfile");
    }

    while (apr_file_gets(line, sizeof(line), ort->userdb) == APR_SUCCESS) {
        char *newline;
        char date[32];
        apr_time_exp_t t;
        apr_size_t tsize, wsize;

        if (strncmp(line, user->username, strlen(user->username)) != 0) {
            rv = apr_file_write_full(tmpfile, line, strlen(line), &wsize);
            if (rv) {
                apr_file_close(tmpfile);
                apr_file_remove(tmpfilename, ort->pool);
                return orthrus_error_create(rv, "Can't write to temporary dbfile");
            }
            continue;
        }

        apr_time_exp_lt(&t, apr_time_now());
        apr_strftime(date, &tsize, sizeof date, "%b %d,%Y %H:%M:%S", &t);
        newline = apr_psprintf(ort->pool, "%s %04d %s %24"  APR_UINT64_T_HEX_FMT "  %s\n",
                           user->username, user->ch.sequence, user->ch.seed,
                           reply, date);
        rv = apr_file_write_full(tmpfile, newline, strlen(newline), &wsize);
        if (rv) {
            apr_file_close(tmpfile);
            apr_file_remove(tmpfilename, ort->pool);
            return orthrus_error_create(rv, "Can't write to temporary dbfile");
        }
        found = 1;
    }
    if (!found) {
        char date[32];
        apr_time_exp_t t;
        apr_size_t tsize, wsize;
        char *newline;

        apr_time_exp_lt(&t, apr_time_now());
        apr_strftime(date, &tsize, sizeof date, "%b %d,%Y %H:%M:%S", &t);
        newline = apr_psprintf(ort->pool, "%s %04d %s %24"  APR_UINT64_T_HEX_FMT "  %s\n",
                               user->username, user->ch.sequence, user->ch.seed,
                               reply, date);
        rv = apr_file_write_full(tmpfile, newline, strlen(newline), &wsize);
        if (rv) {
            apr_file_close(tmpfile);
            apr_file_remove(tmpfilename, ort->pool);
            return orthrus_error_create(rv, "Can't write to temporary dbfile");
        }
    }

    apr_file_close(tmpfile);
    rv = apr_file_rename(tmpfilename, ort->path, 0);

    if (rv)
        return orthrus_error_create(rv, "Can't rename tmpfile to dbfile");

    return ORTHRUS_SUCCESS;
}

/* RFC 2289 Section 7.0 "VERIFICATION OF ONE-TIME PASSWORDS":
 * The server system has a database containing, for each user, the
 * one-time password from the last successful authentication or the
 * first OTP of a newly initialized sequence. To authenticate the user,
 * the server decodes the one-time password received from the generator
 * into a 64-bit key and then runs this key through the secure hash
 * function once. If the result of this operation matches the stored
 * previous OTP, the authentication is successful and the accepted
 * one-time password is stored for future use.
 */

orthrus_error_t* orthrus_userdb_verify(orthrus_t *ort,
                                       const char *username,
                                       const char *challenge,
                                       const char *reply)
{
  apr_uint64_t last = 0, r = 0;
  orthrus_error_t* err;
  orthrus_challenge_t ch;
  orthrus_user_t *user;
  orthrus_response_t *resp;

  err = userdb_get_user(ort, username, &user);
  if (err != ORTHRUS_SUCCESS) {
    return err;
  }

  err = decode_challenge(ort, challenge, &ch);
  if (err != ORTHRUS_SUCCESS) {
    return err;
  }
    
  if (strcmp(ch.seed, user->ch.seed) != 0) {
    return orthrus_error_create(APR_EGENERAL, "seed changed between challenge and verification.");
  }

  if (ch.sequence != user->ch.sequence - 1) {
    return orthrus_error_create(APR_EGENERAL, "sequence changed between challenge and verification.");
  }

  err = decode_reply(ort, reply, &resp);

  if (err != ORTHRUS_SUCCESS) {
    return err;
  }

  r = resp->reply;

  err = orthrus__alg_md5_cycle(1, resp);
  if (err != ORTHRUS_SUCCESS) {
    return err;
  }

  orthrus__decode_hex(user->lastreply, &last);
  
  if (last != resp->reply) {
    return orthrus_error_create(APR_EGENERAL, "invalid response.");
  }

  user->ch.sequence--;
  return update_db(ort, user, r);
}

orthrus_error_t* orthrus_userdb_save(orthrus_t *ort,
                                     const char *username,
                                     const char *challenge,
                                     const char *reply)
{
    orthrus_response_t *resp;
    orthrus_user_t user;
    orthrus_error_t *err;

    user.username = username;
    user.lastreply = NULL;

    err = decode_reply(ort, reply, &resp);
    if (err != ORTHRUS_SUCCESS)
        return err;

    err = decode_challenge(ort, challenge, &user.ch);
    if (err != ORTHRUS_SUCCESS)
        return err;

    return update_db(ort, &user, resp->reply);
}
