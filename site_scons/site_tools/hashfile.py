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

"""HashFile builder: writes a BSD-style digest file next to each source.

env.HashFile('orthrus-0.8.0.tar.bz2') produces one file per algorithm in
$HASHFILE_ALGS, e.g. orthrus-0.8.0.tar.bz2.sha1 containing:

    SHA1(orthrus-0.8.0.tar.bz2)= 0123...
"""

import hashlib
from os.path import basename

import SCons.Action

# ripemd160 is only present when the OpenSSL build backing hashlib still
# carries it; modern distributions drop it, so the list gets filtered at
# generate() time rather than exploding mid-build.
DEFAULT_ALGS = ['md5', 'sha1', 'ripemd160']


def _available_algs(algs):
  available = []
  for alg in algs:
    try:
      hashlib.new(alg)
    except (ValueError, TypeError):
      continue
    available.append(alg)
  return available


def hashfile_string(target, source, env):
  return 'hashfile(%s)' % (str(source[0]))


def hashfile_emitter(target, source, env):
  targets = [str(source[0]) + '.' + alg for alg in env['HASHFILE_ALGS']]
  return targets, source


def hashfile(target, source, env):
  contents = source[0].get_contents()
  name = basename(str(source[0]))

  # Walk targets alongside the algorithms the emitter derived them from, so
  # the digest always lands in the node SCons is tracking.
  for tgt, alg in zip(target, env['HASHFILE_ALGS']):
    h = hashlib.new(alg)
    h.update(contents)
    with open(str(tgt), 'w') as fp:
      fp.write('%s(%s)= %s\n' % (alg.upper(), name, h.hexdigest()))


def generate(env):
  env['HASHFILE_ALGS'] = _available_algs(DEFAULT_ALGS)
  env.Append(BUILDERS={
      'HashFile': env.Builder(
          action=SCons.Action.Action(hashfile, hashfile_string),
          emitter=hashfile_emitter,
          target_factory=env.fs.Entry),
  })


def exists(env):
  return True
