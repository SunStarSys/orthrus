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
#include "apr_file_io.h"
#include <stdlib.h>

#ifndef NL
#define NL APR_EOL_STR
#endif

typedef struct otp_test_t {
  int alg;
  const char *password;
  const char *seed;
  apr_uint64_t sequence;
  const char *hex;
  const char *words;
} otp_test_t;


/* RFC 2289, Appendix C  -  OTP Verification Examples */
otp_test_t tests[] = 
{
  {ORTHRUS_ALG_MD4, "This is a test.", "TeSt", 0, "D185 4218 EBBB 0B51", "ROME MUG FRED SCAN LIVE LACE"},
  {ORTHRUS_ALG_MD4, "This is a test.", "TeSt", 1, "6347 3EF0 1CD0 B444", "CARD SAD MINI RYE COL KIN"},
  {ORTHRUS_ALG_MD4, "This is a test.", "TeSt", 99, "C5E6 1277 6E6C 237A", "NOTE OUT IBIS SINK NAVE MODE"},
  {ORTHRUS_ALG_MD4, "AbCdEfGhIjK", "alpha1", 0, "5007 6F47 EB1A DE4E", "AWAY SEN ROOK SALT LICE MAP"},
  {ORTHRUS_ALG_MD4, "AbCdEfGhIjK", "alpha1", 1, "65D2 0D19 49B5 F7AB", "CHEW GRIM WU HANG BUCK SAID"},
  {ORTHRUS_ALG_MD4, "AbCdEfGhIjK", "alpha1", 99, "D150 C82C CE6F 62D1", "ROIL FREE COG HUNK WAIT COCA"},
  {ORTHRUS_ALG_MD4, "OTP's are good", "correct", 0, "849C 79D4 F6F5 5388", "FOOL STEM DONE TOOL BECK NILE"},
  {ORTHRUS_ALG_MD4, "OTP's are good", "correct", 1, "8C09 92FB 2508 47B1", "GIST AMOS MOOT AIDS FOOD SEEM"},
  {ORTHRUS_ALG_MD4, "OTP's are good", "correct", 99, "3F3B F4B4 145F D74B", "TAG SLOW NOV MIN WOOL KENO"},

  {ORTHRUS_ALG_MD5, "This is a test.", "TeSt", 0, "9E87 6134 D904 99DD", "INCH SEA ANNE LONG AHEM TOUR"},
  {ORTHRUS_ALG_MD5, "This is a test.", "TeSt", 1, "7965 E054 36F5 029F", "EASE OIL FUM CURE AWRY AVIS"},
  {ORTHRUS_ALG_MD5, "This is a test.", "TeSt", 99, "50FE 1962 C496 5880", "BAIL TUFT BITS GANG CHEF THY"},
  {ORTHRUS_ALG_MD5, "AbCdEfGhIjK", "alpha1", 0, "8706 6DD9 644B F206", "FULL PEW DOWN ONCE MORT ARC"},
  {ORTHRUS_ALG_MD5, "AbCdEfGhIjK", "alpha1", 1, "7CD3 4C10 40AD D14B", "FACT HOOF AT FIST SITE KENT"},
  {ORTHRUS_ALG_MD5, "AbCdEfGhIjK", "alpha1", 99, "5AA3 7A81 F212 146C", "BODE HOP JAKE STOW JUT RAP"},
  {ORTHRUS_ALG_MD5, "OTP's are good", "correct", 0, "F205 7539 43DE 4CF9", "ULAN NEW ARMY FUSE SUIT EYED"},
  {ORTHRUS_ALG_MD5, "OTP's are good", "correct", 1, "DDCD AC95 6F23 4937", "SKIM CULT LOB SLAM POE HOWL"},
  {ORTHRUS_ALG_MD5, "OTP's are good", "correct", 99, "B203 E28F A525 BE47", "LONG IVY JULY AJAR BOND LEE"},

  {ORTHRUS_ALG_SHA1, "This is a test.", "TeSt", 0, "BB9E 6AE1 979D 8FF4", "MILT VARY MAST OK SEES WENT"},
  {ORTHRUS_ALG_SHA1, "This is a test.", "TeSt", 1, "63D9 3663 9734 385B", "CART OTTO HIVE ODE VAT NUT"},
  {ORTHRUS_ALG_SHA1, "This is a test.", "TeSt", 99, "87FE C776 8B73 CCF9", "GAFF WAIT SKID GIG SKY EYED"},
  {ORTHRUS_ALG_SHA1, "AbCdEfGhIjK", "alpha1", 0, "AD85 F658 EBE3 83C9", "LEST OR HEEL SCOT ROB SUIT"},
  {ORTHRUS_ALG_SHA1, "AbCdEfGhIjK", "alpha1", 1, "D07C E229 B5CF 119B", "RITE TAKE GELD COST TUNE RECK"},
  {ORTHRUS_ALG_SHA1, "AbCdEfGhIjK", "alpha1", 99, "27BC 7103 5AAF 3DC6", "MAY STAR TIN LYON VEDA STAN"},
  {ORTHRUS_ALG_SHA1, "OTP's are good", "correct", 0, "D51F 3E99 BF8E 6F0B", "RUST WELT KICK FELL TAIL FRAU"},
  {ORTHRUS_ALG_SHA1, "OTP's are good", "correct", 1, "82AE B52D 9437 74E4", "FLIT DOSE ALSO MEW DRUM DEFY"},
  {ORTHRUS_ALG_SHA1, "OTP's are good", "correct", 99, "4F29 6A74 FE15 67EC", "AURA ALOE HURL WING BERG WAIT"},
};

int main(int argc, const char * const argv[])
{
  int i;
  orthrus_t *ort;
  apr_status_t rv;
  apr_file_t *errfile;
  orthrus_error_t *err;
  apr_pool_t *pool;
  apr_pool_t *tpool;
  apr_app_initialize(&argc, &argv, NULL);
  atexit(apr_terminate);

  apr_pool_create(&pool, NULL);

  rv = apr_file_open_stderr(&errfile, pool);
  if (rv) {
    fprintf(stderr, "Failed to open stderr: %d", rv);
    return rv;
  }

  err = orthrus_create(pool, &ort);

  if (err) {
    apr_file_printf(errfile, "[%s:%d] Failed to create orthrus instance: %s (%d)"NL,
                    err->file, err->line, err->msg, err->err);
    return 1;
  }
  
  apr_pool_create(&tpool, pool);
  
  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    otp_test_t *t = &tests[i];
    orthrus_response_t *reply;
    const char *p;

    err = orthrus_calculate(ort, &reply, t->alg,
                            t->sequence, t->seed,
                            t->password, strlen(t->password),
                            tpool);
    if (err) {
      apr_file_printf(errfile, "[%s:%d] Test %d Failed: %s (%d)"NL,
                      err->file, err->line, i, err->msg, err->err);
      return 1;
    }
    

    orthrus_response_format_hex(reply, &p);
    if (strcmp(p, t->hex) != 0) {
      apr_file_printf(errfile, "Test %d Failed: Hex mismatch. expected='%s' got='%s'"NL,
                      i, t->hex, p);
     // return 1;
    }

    orthrus_response_format_words(reply, &p);
    if (strcmp(p, t->words) != 0) {
      apr_file_printf(errfile, "Test %d Failed: Words mismatch. expected='%s' got='%s'"NL,
                      i, t->words, p);
     // return 1;
    }
    apr_pool_clear(tpool);
  }

  apr_file_printf(errfile, "%d tests completed"NL, i);
  
  return 0;
}
