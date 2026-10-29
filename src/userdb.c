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

  /* APR_BUFFERED is not a nicety here. apr_file_gets() on an unbuffered APR
   * file fetches one byte per apr_file_read(), which is one read(2) per byte
   * of the database: 610,068 syscalls to scan a 610KB file, and ~109ms to
   * reach the last record. Buffered, the same scan is a few hundred reads. */
  rv = apr_file_open(&ort->userdb, path,
                     APR_READ|APR_WRITE|APR_CREATE|APR_BINARY|APR_BUFFERED,
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
  apr_uint64_t scratch;
  orthrus_error_t *err;

  err = orthrus__validate_username(username);
  if (err) {
    return err;
  }

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

    /* Every field below is validated as it is read, so a corrupt or
     * hand-edited record is reported against its line number instead of
     * surfacing later as a mystery authentication failure. */
    err = orthrus__validate_sequence(v, &user->ch.sequence);
    if (err) {
      orthrus_error_destroy(err);
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d:"
                                   " sequence is not a decimal number", lineno);
    }

    v = apr_strtok(NULL, " ", &strtok_state);
    if (!v) {
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d", lineno);
    }

    err = orthrus__validate_seed(v);
    if (err) {
      orthrus_error_destroy(err);
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d:"
                                   " seed is not 1 to %d alphanumeric"
                                   " characters", lineno, ORTHRUS_MAX_SEED_LEN);
    }

    user->ch.seed = apr_pstrdup(ort->pool, v);

    v = apr_strtok(NULL, " ", &strtok_state);
    if (!v) {
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d", lineno);
    }

    err = orthrus__decode_hex(v, &scratch);
    if (err) {
      orthrus_error_destroy(err);
      return orthrus_error_createf(APR_EGENERAL, "userdb corrupted at line %d:"
                                   " stored response is not hexadecimal",
                                   lineno);
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

  /* Sequence 0 means the chain is used up. Without this the subtraction
   * below wraps an apr_uint32_t to 4294967295 and hands out challenges for
   * a sequence that was never initialised. */
  if (user->ch.sequence == 0) {
    return orthrus_error_create(APR_EGENERAL,
                                "OTP sequence is exhausted, re-initialize "
                                "it with ortpasswd");
  }

  /* TODO: Configurable algorithms */
  *challenge = apr_psprintf(pool, "otp-sha1 %u %s", user->ch.sequence - 1,  user->ch.seed);

  return ORTHRUS_SUCCESS;
}

static orthrus_error_t* decode_challenge(orthrus_t *ort,
                                         const char *challenge,
                                         orthrus_challenge_t *ch)
{
  char *strtok_state;
  char *v;
  char *p;
  orthrus_error_t *err;

  if (challenge == NULL) {
    return orthrus_error_create(APR_EGENERAL, "no challenge string given");
  }

  p = apr_pstrdup(ort->pool, challenge);

  /* The four bytes used to be skipped on the strength of a length check
   * alone, so anything at all could sit in front of the algorithm name.
   * strncmp stops at a NUL, so no length check is needed to be safe. */
  if (strncmp(p, "otp-", 4) != 0) {
    return orthrus_error_create(APR_EGENERAL,
                                "challenge does not begin with 'otp-'.");
  }

  p += 4;

  if (strncmp("sha1 ", p, 5) != 0) {
    return orthrus_error_create(APR_ENOTIMPL, "only sha1 verification is supported.");
  }

  p += 5;

  v = apr_strtok(p, " ", &strtok_state);

  if (!v) {
    return orthrus_error_create(APR_EGENERAL, "invalid challenge string when looking for sequence.");
  }

  err = orthrus__validate_sequence(v, &ch->sequence);
  if (err) {
    return err;
  }

  v = apr_strtok(NULL, " ", &strtok_state);
  if (!v) {
    return orthrus_error_create(APR_EGENERAL,
                                "invalid challenge string when looking for seed.");
  }

  err = orthrus__validate_seed(v);
  if (err) {
    return err;
  }

  ch->seed = apr_pstrdup(ort->pool, v);

  return ORTHRUS_SUCCESS;
}

static orthrus_error_t* decode_reply(orthrus_t *ort,
                                    const char *reply,
                                    orthrus_response_t **out_resp)
{
  orthrus_response_t *resp;
  orthrus_error_t *err;
  /* TODO: Support Six word dictionary decoding.
   *  (note, its just a SHOULD from the RFC) */

  /* RFC 2289 Section 6.0, "Form of Output":
   * If a six-word encoded one-time password is valid, it is accepted.
   * Otherwise, if the one-time password can be interpreted as hexadecimal, and
   * with that decoding it is valid, then it is accepted.*/
  if (reply == NULL) {
    return orthrus_error_create(APR_BADARG, "no response given");
  }

  resp = apr_pcalloc(ort->pool, sizeof(orthrus_response_t));
  resp->pool = ort->pool;

  err = orthrus__decode_words(reply, &resp->reply);
  if (err) {
    orthrus_error_destroy(err);

    /* Not six words, so it has to be the hexadecimal form. If that fails
     * too the response is simply malformed: previously both decoders could
     * fail and we carried on with whatever was left in resp->reply (zero,
     * for anything with no hex digits at all) and hashed it anyway. */
    err = orthrus__decode_hex(reply, &resp->reply);
    if (err) {
      return err;
    }
  }

  *out_resp =  resp;

  return ORTHRUS_SUCCESS;
}

/* Does this userdb line belong to username?
 *
 * The whole first field has to match. A bare strncmp() prefix test also
 * matches "bobby" and "bobbysue" while updating "bob", and update_db() then
 * rewrites those records as the user being updated -- destroying their
 * credentials. Fields are separated by ' ', which is how userdb_get_user()
 * tokenizes and how the records below are written.
 */
static int line_matches_user(const char *line, const char *username)
{
    apr_size_t len = strlen(username);

    return strncmp(line, username, len) == 0 && line[len] == ' ';
}

static
orthrus_error_t* update_db(orthrus_t *ort, orthrus_user_t *user, apr_uint64_t reply)
{
    char line[ORT_USERDB_MAX_LINE_LEN], *tmpfilename;
    int found = 0;
    apr_status_t rv;
    apr_file_t *tmpfile;
    apr_off_t start = 0;

    /* Unique name, created O_CREAT|O_EXCL, so we never write through a file
     * that was already there. A fixed ".tmp" opened without APR_TRUNCATE let
     * trailing bytes of a longer previous file survive past the new contents
     * and get renamed over the userdb: a stale file from a crash corrupts the
     * database, and a planted one injects an entry outright. APR_EXCL also
     * means we cannot be redirected through a symlink left at that path.
     */
    tmpfilename = apr_pstrcat(ort->pool, ort->path, ".tmpXXXXXX", NULL);
    rv = apr_file_mktemp(&tmpfile, tmpfilename,
                         APR_CREATE|APR_EXCL|APR_READ|APR_WRITE|APR_BINARY|
                         APR_BUFFERED,
                         ort->pool);
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

        if (!line_matches_user(line, user->username)) {
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

  if (user->ch.sequence == 0) {
    return orthrus_error_create(APR_EGENERAL,
                                "OTP sequence is exhausted, re-initialize "
                                "it with ortpasswd");
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

  err = orthrus__alg_sha1_cycle(1, resp);
  if (err != ORTHRUS_SUCCESS) {
    return err;
  }

  err = orthrus__decode_hex(user->lastreply, &last);
  if (err != ORTHRUS_SUCCESS) {
    return err;
  }

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

    /* This path writes a brand new record, and unlike the lookups it never
     * passes through userdb_get_user(), so nothing else checks the name. */
    err = orthrus__validate_username(username);
    if (err)
        return err;

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
