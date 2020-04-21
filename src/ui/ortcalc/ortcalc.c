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
#ifndef WIN32
#include <unistd.h>
#include <termios.h>
#endif

#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* for atexit() */
#endif

#include <strings.h>


#ifndef NL
#define NL APR_EOL_STR
#endif

#ifndef PW_MAX_LEN
#define PW_MAX_LEN 1024
#endif

typedef struct ortcalc_t {
  apr_pool_t *pool;
  apr_file_t *errfile;
  apr_file_t *outfile;
  const char *shortname;
  orthrus_t *ort;
  char pwin[PW_MAX_LEN];
  apr_uint64_t num;
  const char *seed;
  int showhex;
} ortcalc_t;


static orthrus_error_t* acquire_password(ortcalc_t *oc)
{
  apr_status_t rv;
  apr_size_t bufsize = sizeof(oc->pwin);
#ifndef WIN32
  struct termios term;
#endif

  apr_file_printf(oc->errfile, "Password: ");

#ifndef WIN32
  if (isatty(STDIN_FILENO)) {
      struct termios noecho;
      tcgetattr(STDIN_FILENO, &term);
      noecho = term;
      noecho.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
      tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
  }
#endif

  rv  = read(STDIN_FILENO, oc->pwin, bufsize - 1);

#ifndef WIN32
  if (isatty(STDIN_FILENO))
      tcsetattr(STDIN_FILENO, TCSANOW, &term);
#endif

  apr_file_printf(oc->errfile, "\n");

  if (rv <= 0) {
      return orthrus_error_create(rv, "Failed to read password");
  }

  oc->pwin[rv] = 0;
  while (oc->pwin[--rv] == '\n' || oc->pwin[rv] == '\r')
      oc->pwin[rv] = 0;

  return ORTHRUS_SUCCESS;
}

static void usage(ortcalc_t *oc)
{
  apr_file_printf(oc->errfile,
    "%s -- Program to calculate OTP responses" NL
    "Usage: %s [-VhH] [sequence] [seed]"
    ""NL
    "   -V   Print version information and exit." NL
    "   -h   Print help text and exit." NL NL
    "   -H   Output Hex Response" NL
    ""NL,
    oc->shortname,
    oc->shortname);
}

int main(int argc, const char * const argv[])
{
  apr_getopt_t *opt;
  const char *optarg;
  char ch;
  orthrus_response_t *reply;
  ortcalc_t oc;
  apr_status_t rv = APR_SUCCESS;
  orthrus_error_t *err;

  apr_app_initialize(&argc, &argv, NULL);
  atexit(apr_terminate);

  memset(&oc, 0, sizeof(ortcalc_t));

  apr_pool_create(&oc.pool, NULL);

  rv = apr_file_open_stderr(&oc.errfile, oc.pool);
  if (rv) {
    fprintf(stderr, "Failed to open stderr: %d", rv);
    return rv;
  }

  rv = apr_file_open_stdout(&oc.outfile, oc.pool);
  if (rv) {
    apr_file_printf(oc.errfile, "failed to open stdout: (%d)"NL,
                    rv);
    return 1;
  }
  
  if (argc) {
    oc.shortname = apr_filepath_name_get(argv[0]);
  }
  else {
    oc.shortname = "ortcalc";
  }
  
  err = orthrus_create(oc.pool, &oc.ort);

  if (err) {
    apr_file_printf(oc.errfile, "[%s:%d] Failed to create orthrus instance: %s (%d)"NL,
                    err->file, err->line, err->msg, err->err);
    return 1;
  }

  rv = apr_getopt_init(&opt, oc.pool, argc, argv);
  
  if (rv != APR_SUCCESS) {
    apr_file_printf(oc.errfile, "apr_getopt_init failed."NL );
    return 1;
  }

  if (argc <= 1) {
    usage(&oc);
    return 1;
  }
  
  opt->interleave = 1;
  
  while ((rv = apr_getopt(opt, "VhH", &ch, &optarg)) == APR_SUCCESS) {
    switch (ch) {
      case 'V':
        apr_file_printf(oc.outfile, "%s %s" NL, oc.shortname, ORTHRUS_VERSION_STRING);
        return 0;
      case 'h':
        usage(&oc);
        return 0;
      case 'H':
        oc.showhex = 1;
    }
  }
  
  if (rv != APR_EOF) {
    apr_file_printf(oc.errfile, "Error: Parsing Arguments Failed" NL NL);
    usage(&oc);
    return 1;
  }

  if (argc - opt->ind != 2) {
    apr_file_printf(oc.errfile, "Error: Expected sequence and seed, but none found" NL NL);
    usage(&oc);
    return 1;
  }

  oc.num = apr_atoi64(opt->argv[opt->ind]);
  oc.seed = apr_pstrdup(oc.pool, opt->argv[opt->ind+1]);

  err = acquire_password(&oc);
  if (err) {
    apr_file_printf(oc.errfile, "[%s:%d] acquire_password: %s (%d)"NL,
                    err->file, err->line, err->msg, err->err);
    return 1;
  }

  err = orthrus_calculate(oc.ort, &reply, ORTHRUS_ALG_MD5,
                          oc.num, oc.seed,
                          oc.pwin, strlen(oc.pwin),
                          oc.pool);

  bzero(oc.pwin, sizeof oc.pwin);

  if (err) {
    apr_file_printf(oc.errfile, "[%s:%d] Failed to calculate OTP: %s (%d)"NL,
                    err->file, err->line, err->msg, err->err);
    return 1;
  }
  else {
    const char *output;

    if (oc.showhex) {
      orthrus_response_format_hex(reply, &output);
    }
    else {
      orthrus_response_format_words(reply, &output);
    }

    apr_file_printf(oc.outfile, "%s"NL, output);
  }


  return 0;
}

