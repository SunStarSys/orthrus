/* Copyright 2007 Paul Querna.
 * Copyright 2006 Garrett Rooney.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "orthrus_error.h"
#include "apr_strings.h"

orthrus_error_t*
orthrus_error_create_impl(apr_status_t err,
                          const char *msg,
                          uint32_t line,
                          const char *file)
{
    orthrus_error_t *e;
    
    e = malloc(sizeof(*e));

    e->err = err;
    e->msg = strdup(msg);
    e->line = line;
    e->file = strdup(file);
    
    return e;
}

orthrus_error_t *
orthrus_error_createf_impl(apr_status_t err,
                           uint32_t line,
                           const char *file,
                           const char *fmt,
                           ...)
{
    orthrus_error_t *e;
    va_list ap, aq;
    apr_size_t s;

    e = malloc(sizeof(*e));

    e->err = err;

    va_start(ap, fmt);
    va_copy(aq, ap);

#ifdef HAVE_VASPRINTF
    vasprintf((char **)&e->msg, fmt, ap);
#else
    s = apr_vsnprintf(NULL, 0, fmt, ap);
    e->msg = malloc(s + 1);
    apr_vsnprintf((char *)e->msg, s + 1, fmt, aq);
#endif

    va_end(ap);
    va_end(aq);

    e->line = line;
    e->file = strdup(file);

    return e;
}

void
orthrus_error_destroy(orthrus_error_t *err)
{
    if (err) {
        free((void *) err->msg);
        free((void *) err->file);
        free(err);
    }
}
