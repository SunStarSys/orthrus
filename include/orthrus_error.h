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

/**
 * @file orthrus_error.h
 * @brief Error Objects for Orthrus.
 */

#ifndef _ORTHRUS_ERROR_H_
#define _ORTHRUS_ERROR_H_

#include <apr.h>
#include <apr_errno.h>
#include <apr_pools.h>

/* Based upon Protoon's Error Objects, which are based on ETL's, which are
 * based on Subversion's.  You get the idea.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Check if the @c orthrus_error_t returned by @a expression is equal to
 * @c ORTHRUS_SUCCESS.  If it is, do nothing, if not, then return it.
 */
#define ORT_ERR(expression) do {              \
    orthrus_error_t *ort__err = (expression); \
    if (ort__err)                             \
      return ort__err;                        \
} while (0)

/** Successful return value for a function that returns @c orthrus_error_t. */
#define ORTHRUS_SUCCESS NULL

/** An exception object. */
typedef struct {
    apr_status_t err;
    const char *msg;
    
    apr_uint32_t line;
    const char *file;
    
    apr_pool_t *pool;
} orthrus_error_t;

/**
* Return a new @c orthrus_error_t with underlying @c apr_status_t @a err
 * and message @a msg.
 */
#define orthrus_error_create(err, msg) orthrus_error_create_impl(err,      \
                                                         msg,      \
                                                         __LINE__, \
                                                         __FILE__)

/**
* The underlying function that implements @c orthrus_error_create.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
orthrus_error_t *
orthrus_error_create_impl(apr_status_t err,
                      const char *msg,
                      apr_uint32_t line,
                      const char *file);

/**
* Return a new @c orthrus_error_t with underlying @c apr_status_t @a err
 * and message created @c printf style with @a fmt and varargs.
 */
#define orthrus_error_createf(err, fmt, ...) orthrus_error_createf_impl(err,         \
                                                                  __LINE__,    \
                                                                  __FILE__,    \
                                                                  fmt,         \
                                                                  __VA_ARGS__)

/**
* The underlying function that implements @c orthrus_error_createf.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
orthrus_error_t *
orthrus_error_createf_impl(apr_status_t err,
                           apr_uint32_t line,
                           const char *file,
                           const char *fmt,
                           ...);

/** Destroy @a err. */
void orthrus_error_destroy(orthrus_error_t *err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _ORTHRUS_ERROR_H_ */
