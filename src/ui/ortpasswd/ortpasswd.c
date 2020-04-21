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
#include "orthrus_version.h"

#include "apr_file_io.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_getopt.h"
#include "apr_time.h"
#include <ctype.h>

#ifndef WIN32
#include <unistd.h>
#include <termios.h>
#endif

#include <sys/types.h>
#include <pwd.h>

#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* for atexit() */
#endif


#ifndef NL
#define NL APR_EOL_STR
#endif

#ifndef PW_MAX_LEN
#define PW_MAX_LEN 1024
#endif

#define INIT_SEQ 500

typedef struct ortpasswd_t {
  apr_pool_t *pool;
  apr_file_t *errfile;
  apr_file_t *outfile;
  const char *shortname;
  orthrus_t *ort;
  const char *user;
  char pwin[PW_MAX_LEN];
  apr_uint64_t num;
  const char *seed;
} ortpasswd_t;


static orthrus_error_t* acquire_password(ortpasswd_t *op)
{
  apr_status_t rv;
  apr_size_t bufsize = sizeof(op->pwin);
#ifndef WIN32
  struct termios term;
#endif

  apr_file_printf(op->errfile, "Password: ");

#ifndef WIN32
  if (isatty(STDIN_FILENO)) {
      struct termios noecho;
      tcgetattr(STDIN_FILENO, &term);
      noecho = term;
      noecho.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
      tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
  }
#endif

  rv  = read(STDIN_FILENO, op->pwin, bufsize - 1);

#ifndef WIN32
  if (isatty(STDIN_FILENO))
      tcsetattr(STDIN_FILENO, TCSANOW, &term);
#endif

  apr_file_printf(op->errfile, "\n");

  if (rv <= 0) {
      return orthrus_error_create(rv, "Failed to read password");
  }

  op->pwin[rv] = 0;
  while (op->pwin[--rv] == '\n' || op->pwin[rv] == '\r')
      op->pwin[rv] = 0;

  return ORTHRUS_SUCCESS;
}

static void usage(ortpasswd_t *op)
{
  apr_file_printf(op->errfile,
    "%s -- Program to initialize OTP server responses" NL
    "Usage: %s [-VhH]"NL
    ""NL
    "   -V   Print version information and exit." NL
    "   -h   Print help text and exit." NL NL
    "   -H   Output Hex Response" NL
    ""NL,
    op->shortname,
    op->shortname);
}

int main(int argc, const char * const argv[])
{
  apr_getopt_t *opt;
  const char *optarg;
  char ch;
  ortpasswd_t op;
  apr_status_t rv = APR_SUCCESS;
  orthrus_error_t *err;
  const char *ortuserdb = "/etc/orthruskeys";
  struct passwd *pwd;
  const char *challenge;
  int rand;
  char hostname[256];

  apr_app_initialize(&argc, &argv, NULL);
  atexit(apr_terminate);

  memset(&op, 0, sizeof(ortpasswd_t));

  apr_pool_create(&op.pool, NULL);

  rv = apr_file_open_stderr(&op.errfile, op.pool);
  if (rv) {
    fprintf(stderr, "Failed to open stderr: %d", rv);
    return rv;
  }

  rv = apr_file_open_stdout(&op.outfile, op.pool);
  if (rv) {
    apr_file_printf(op.errfile, "failed to open stdout: (%d)"NL,
                    rv);
    return 1;
  }
  
  if (argc) {
    op.shortname = apr_filepath_name_get(argv[0]);
  }
  else {
    op.shortname = "ortpasswd";
  }
  
  err = orthrus_create(op.pool, &op.ort);

  if (err) {
    apr_file_printf(op.errfile, "[%s:%d] Failed to create orthrus instance: %s (%d)"NL,
                    err->file, err->line, err->msg, err->err);
    return 1;
  }

  rv = apr_getopt_init(&opt, op.pool, argc, argv);
  
  if (rv != APR_SUCCESS) {
    apr_file_printf(op.errfile, "apr_getopt_init failed."NL );
    return 1;
  }
  
  while ((rv = apr_getopt(opt, "Vh", &ch, &optarg)) == APR_SUCCESS) {
    switch (ch) {
      case 'V':
        apr_file_printf(op.outfile, "%s %s" NL, op.shortname, ORTHRUS_VERSION_STRING);
        return 0;
      case 'h':
        usage(&op);
        return 0;
    }
  }
  
  if (rv != APR_EOF) {
    apr_file_printf(op.errfile, "Error: Parsing Arguments Failed" NL NL);
    usage(&op);
    return 1;
  }

  pwd = getpwuid(getuid());

  err = orthrus_userdb_open(op.ort, ortuserdb);
  if (err) {
    apr_file_printf(op.errfile, "Error: Cannot open user database" NL);
    return 2;
  }

  err = orthrus_userdb_get_challenge(op.ort, pwd->pw_name, &challenge, op.pool);
  if (err) {
      if (err->err == APR_NOTFOUND) {
          orthrus_userdb_close(op.ort);
          goto generatenewcreds;
      }
      else {
          apr_file_printf(op.errfile, "Error: Failed to get challenge for user %s at '%s': %s (%d)", 
                                   pwd->pw_name, ortuserdb, err->msg, err->err);
          orthrus_userdb_close(op.ort);
          return 3;
      }
  }
  orthrus_userdb_close(op.ort);

  apr_file_printf(op.errfile, "%s"NL, challenge);

  err = acquire_password(&op);
  if (err) {
      apr_file_printf(op.errfile, "Error: Failed to acquire password for user %s: %s (%d)", 
                      pwd->pw_name, err->msg, err->err);
      return 4;
  }

  err = orthrus_userdb_open(op.ort, ortuserdb);
  if (err) {
    apr_file_printf(op.errfile, "Error: Cannot open user database" NL);
    return 2;
  }

  err = orthrus_userdb_verify(op.ort, pwd->pw_name,
                              challenge, op.pwin);
  if (err) {
      apr_file_printf(op.errfile, "Error: Failed to verify password for user %s: %s (%d)", 
                      pwd->pw_name, err->msg, err->err);
      orthrus_userdb_close(op.ort);
      return 5;
  }

  orthrus_userdb_close(op.ort);

generatenewcreds:

  srandom(getpid() ^ apr_time_now());

  rand = random() % 10000; /* close enough */
  rv = gethostname(hostname, sizeof hostname);
  if (rv) {
      apr_file_printf(op.errfile, "Error: hostname longer than %lu" NL , sizeof hostname);
      return 6;
  }

  if (hostname[0]) {
      if (isupper(hostname[0]))
          hostname[0] = tolower(hostname[0]);
      if (hostname[1] && isupper(hostname[1]))
          hostname[1] = tolower(hostname[1]);
  }

  op.seed = apr_psprintf(op.pool, "%.2s%d", hostname, rand);
  op.num = INIT_SEQ;

  challenge = apr_psprintf(op.pool, "otp-md5 %" APR_UINT64_T_FMT " %s", op.num, op.seed);
  apr_file_printf(op.errfile, "%s"NL, challenge);

  err = acquire_password(&op);
  if (err) {
      apr_file_printf(op.errfile, "Error: Failed to acquire password for user %s: %s (%d)", 
                      pwd->pw_name, err->msg, err->err);
      return 4;
  }

  err = orthrus_userdb_open(op.ort, ortuserdb);
  if (err) {
    apr_file_printf(op.errfile, "Error: Cannot open user database" NL);
    return 2;
  }

  err = orthrus_userdb_save(op.ort, pwd->pw_name,
                            challenge, op.pwin);
  if (err) {
      apr_file_printf(op.errfile, "Error: Failed to save password for user %s: %s (%d)", 
                      pwd->pw_name, err->msg, err->err);
      orthrus_userdb_close(op.ort);
      return 5;
  }

  orthrus_userdb_close(op.ort);
  return 0;
}

