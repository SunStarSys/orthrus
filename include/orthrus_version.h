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
 * @file orthrus_version.h
 * @brief Defines the Orthrus version information.
 */

#ifndef _ORTHRUS_VERSION_H_
#define _ORTHRUS_VERSION_H_

#include "apr_general.h"

#define ORTHRUS_MAJOR_VERSION 0
#define ORTHRUS_MINOR_VERSION 8
#define ORTHRUS_PATCH_VERSION 0

#define ORTHRUS_DEVBUILD_BOOLEAN 0

#if ORTHRUS_DEVBUILD_BOOLEAN
#define ORTHRUS_VER_ADD_STRING "-dev"
#else
#define ORTHRUS_VER_ADD_STRING ""
#endif

#define ORTHRUS_VERSION_STRING  APR_STRINGIFY(ORTHRUS_MAJOR_VERSION) "." \
                            APR_STRINGIFY(ORTHRUS_MINOR_VERSION) "." \
                            APR_STRINGIFY(ORTHRUS_PATCH_VERSION) \
                            ORTHRUS_VER_ADD_STRING

#endif /* _ORTHRUS_VERSION_H_ */
