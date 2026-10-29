#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Custom SCons configure tests.

Registered in the SConstruct via Configure(custom_tests={...}).
"""

import struct

# PAM headers live under security/ on some platforms and pam/ on others, and
# the appl/modules split differs too.  Probing all four is how we tell.
PAM_HEADERS = (
    'security/pam_modules.h',
    'pam/pam_modules.h',
    'security/pam_appl.h',
    'pam/pam_appl.h',
)


# From: http://www.scons.org/wiki/AutoconfRecipes
def CheckEndian(context):
  """Returns "little", "big" or "unknown".

  NOTE: this reports the byte order of the interpreter running SCons, not of
  the target the C compiler emits for, so it is wrong under cross-compilation.
  Kept as-is because the only consumer (-DBIGENDIAN) has always worked this
  way; a TryRun-based probe would be the fix if cross builds ever matter.
  """
  context.Message('Checking endianness ... ')

  array = struct.pack('cccc', b'\x01', b'\x02', b'\x03', b'\x04')
  native = struct.unpack('i', array)

  if native == struct.unpack('<i', array):
    context.Result('little')
    return 'little'
  elif native == struct.unpack('>i', array):
    context.Result('big')
    return 'big'

  context.Result('unknown')
  return 'unknown'


def CheckVasprintf(context):
  """Probes for vasprintf(3), gating -DHAVE_VASPRINTF in src/error.c.

  NOTE: the probe does not define _GNU_SOURCE itself; it relies on APR's
  --cppflags having already put -D_GNU_SOURCE in the environment, which is
  what makes glibc declare vasprintf here and in src/error.c alike.  If APR
  ever stops exporting it, this check starts failing (and error.c would fail
  to compile if it did not), so add it explicitly in both places rather than
  only here.
  """
  context.Message('Checking for vasprintf ... ')

  source_file = """
  #include <stdio.h>
  int main(int argc, char **argv)
  {
      char *ret;
      vasprintf(&ret, "", NULL);
      return 0;
  }
  """

  result = context.TryLink(source_file, '.c')
  context.Result(result)
  return result
