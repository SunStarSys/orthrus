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
#include "private/config.h"

/* Skeleton for this module is based upton pam_unix.c from FreeBSD/OpenPAM:
 * http://svn.des.no/svn/openpam/trunk/modules/pam_unix/pam_unix.c 
 */

/*-
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2004-2008 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#if HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#if HAVE_PAM_PAM_MODULES_H
#include <pam/pam_modules.h>
#endif

#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#if HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#endif


#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <syslog.h>

#include <apr_general.h>
#include <apr_strings.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define ORT_LOG_ERR(fmt, args...) syslog(LOG_ERR, fmt , ## args)

/* Under OpenPAM the password belongs to pam_get_authtok() and must not be
 * freed; elsewhere it is ours, from the conversation's response. */
#ifdef OPENPAM
#define ORT_FREE_PASSWORD(p) ((void)(p))
#else
#define ORT_FREE_PASSWORD(p) free(p)
#endif

/* APR is initialised once per process and never terminated.
 *
 * This module used to pair apr_initialize()/apr_terminate() around every
 * authentication. apr_initialize() is reference counted but not atomic, so
 * in a threaded server two concurrent authentications race on the count,
 * and one thread's apr_terminate() can tear down APR's global state while
 * the other is still inside it. A loadable module also has no business
 * terminating global state it does not exclusively own -- in a host that
 * uses APR itself, such as httpd, that teardown is not ours to do.
 *
 * Leaving APR initialised for the life of the process is the conventional
 * answer: the process exiting reclaims it.
 */
static pthread_once_t ort_apr_once = PTHREAD_ONCE_INIT;
static apr_status_t ort_apr_status = APR_SUCCESS;
static unsigned char ort_decoy_salt[16];

static void ort_apr_init(void)
{
  ort_apr_status = apr_initialize();

  if (ort_apr_status == APR_SUCCESS) {
    /* Seeded here so that it happens exactly once, under the same guard,
     * rather than racing in decoy_challenge() below. */
    ort_apr_status = apr_generate_random_bytes(ort_decoy_salt,
                                               sizeof ort_decoy_salt);
  }
}

/* A decoy challenge for a user with no OTP credentials.
 *
 * Returning PAM_USER_UNKNOWN straight away, without ever running the
 * conversation, told an attacker exactly which accounts have OTP enrolled:
 * the result code differed and no password was ever asked for. We now
 * prompt as usual and fail with PAM_AUTH_ERR, so the two cases look alike.
 *
 * The decoy is derived from the user name and a per-process salt, so it is
 * stable within one authentication but not predictable from the source.
 * Note the residual leak: because the salt is per process, repeated probes
 * of the same unknown user vary where a real user's challenge would not.
 * Closing that needs decoy state persisted across processes, which is a
 * design change rather than a fix.
 */
static const char *decoy_challenge(apr_pool_t *pool, const char *user)
{
  apr_uint32_t h = 5381;
  const unsigned char *p;
  unsigned i;

  for (i = 0; i < sizeof ort_decoy_salt; i++) {
    h = (h * 33) ^ ort_decoy_salt[i];
  }
  for (p = (const unsigned char *) user; *p; p++) {
    h = (h * 33) ^ *p;
  }

  /* Same shape a real challenge has: two letters then four digits. */
  return apr_psprintf(pool, "otp-sha1 %u %c%c%04u",
                      400 + (h % 100),
                      'a' + (h % 26), 'a' + ((h >> 5) % 26),
                      (h >> 10) % 10000);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{
  orthrus_t *ort;
  apr_pool_t *pool;
  orthrus_error_t *err;
  const char *challenge;
  const char *ortuserdb = "/etc/orthruskeys";
  char *password_prompt;
#ifndef OPENPAM
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
#endif
	struct passwd *pwd;
	const char *user;
	char *password = NULL;
	int pam_err, retry;
  int unknown_user = 0;

	(void)argc;
	(void)argv;

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		return (pam_err);
  }

	if ((pwd = getpwnam(user)) == NULL) {
		return (PAM_USER_UNKNOWN);
  }

  pthread_once(&ort_apr_once, ort_apr_init);
  if (ort_apr_status != APR_SUCCESS) {
    ORT_LOG_ERR("pam_orthrus: apr_initialize failed with: %d", ort_apr_status);
    return (PAM_SYSTEM_ERR);
  }

  apr_pool_create(&pool, NULL);

  err = orthrus_create(pool, &ort);
  if (err) {
    ORT_LOG_ERR("pam_orthrus: create failed with: %s (%d)", err->msg, err->err);
    orthrus_error_destroy(err);
    apr_pool_destroy(pool);
		return (PAM_SYSTEM_ERR);
  }

  /* TODO: Get params from PAM  and make a compile time default */
  err = orthrus_userdb_open(ort, ortuserdb);
  if (err) {
    ORT_LOG_ERR("pam_orthrus: Failed to open userdb at '%s': %s (%d)",
                ortuserdb, err->msg, err->err);
    orthrus_error_destroy(err);
    apr_pool_destroy(pool);
		return (PAM_SYSTEM_ERR);
  }

  err = orthrus_userdb_get_challenge(ort, pwd->pw_name, &challenge, pool);
  if (err) {
    if (err->err == APR_NOTFOUND) {
      /* No OTP credentials. Carry on with a decoy challenge and fail after
       * the conversation, so this is indistinguishable from a wrong
       * one-time password. */
      orthrus_error_destroy(err);
      unknown_user = 1;
      challenge = decoy_challenge(pool, pwd->pw_name);
      if (challenge == NULL) {
        orthrus_userdb_close(ort);
        apr_pool_destroy(pool);
        return (PAM_SYSTEM_ERR);
      }
    }
    else {
      ORT_LOG_ERR("pam_orthrus: failed to get challenge for user %s at '%s': %s (%d)",
                  pwd->pw_name, ortuserdb, err->msg, err->err);
      orthrus_error_destroy(err);
      orthrus_userdb_close(ort);
      apr_pool_destroy(pool);
      return (PAM_SYSTEM_ERR);
    }
  }

  err = orthrus_userdb_close(ort);
  if (err) {
    ORT_LOG_ERR("pam_orthrus: Failed to close userdb at '%s': %s (%d)", ortuserdb, err->msg, err->err);
    orthrus_error_destroy(err);
    apr_pool_destroy(pool);
		return (PAM_SYSTEM_ERR);
  }
  
  /* TODO: Figure out prompting in the 'new' OpenPAM */
	/* get password */
  password_prompt = apr_psprintf(pool, "%s\nPassword: ", challenge);
#ifndef OPENPAM
	pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (pam_err != PAM_SUCCESS) {
    apr_pool_destroy(pool);
		return (PAM_SYSTEM_ERR);
  }
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;
	msgp = &msg;
#endif
	for (retry = 0; retry < 3; ++retry) {
#ifdef OPENPAM
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
                              (const char **)&password, password_prompt);
#else
		resp = NULL;
		pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		if (resp != NULL) {
			if (pam_err == PAM_SUCCESS) {
				password = resp->resp;
      }
			else {
				free(resp->resp);
      }
			free(resp);
		}
#endif
		if (pam_err == PAM_SUCCESS) {
			break;
    }
	}

  if (pam_err == PAM_CONV_ERR) {
    ORT_FREE_PASSWORD(password);
    apr_pool_destroy(pool);
		return (pam_err);
  }

	if (pam_err != PAM_SUCCESS) {
    ORT_FREE_PASSWORD(password);
    apr_pool_destroy(pool);
		return (PAM_AUTH_ERR);
  }

  /* A conversation may report success and still hand back nothing. */
  if (password == NULL) {
    apr_pool_destroy(pool);
		return (PAM_AUTH_ERR);
  }

  /* The user has no credentials; everything above ran only so that this
   * looks the same as a wrong one-time password. */
  if (unknown_user) {
    ORT_FREE_PASSWORD(password);
    apr_pool_destroy(pool);
		return (PAM_AUTH_ERR);
  }

  err = orthrus_userdb_open(ort, ortuserdb);
  if (err) {
    ORT_LOG_ERR("pam_orthrus: Failed to open userdb at '%s' to verify: %s (%d)", ortuserdb, err->msg, err->err);
    orthrus_error_destroy(err);
    ORT_FREE_PASSWORD(password);
    apr_pool_destroy(pool);
		return (PAM_SYSTEM_ERR);
  }

	/* compare passwords */
  err = orthrus_userdb_verify(ort, pwd->pw_name,
                              challenge, password);
  if (err) {
    ORT_LOG_ERR("pam_orthrus: User authentication failed: %s (%d)", err->msg, err->err);
		pam_err = PAM_AUTH_ERR;
    orthrus_error_destroy(err);
  }
	else {
		pam_err = PAM_SUCCESS;
  }

  orthrus_userdb_close(ort);

  apr_pool_destroy(pool);
  ORT_FREE_PASSWORD(password);
	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
               int argc, const char *argv[])
{
  
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char *argv[])
{
  
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{
  
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, const char *argv[])
{
  
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                 int argc, const char *argv[])
{
  
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_orthrus");
#endif

