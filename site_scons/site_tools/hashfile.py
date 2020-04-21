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
# Unless required by applicable law or agreed to in writing, software#
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import SCons.Action

def hashfile_string(target, source, env):
  return "hashfile(%s)" % (str(source[0]))
  
def hashfile_emitter(target, source, env):
  targets = []
  for alg in env['HASHFILE_ALGS']:
    targets.append(str(source[0]) +"."+ alg)
  return targets, source

def hashfile(target, source, env):
  import hashlib
  from os.path import basename
  for alg in  env['HASHFILE_ALGS']:
    h = hashlib.new(alg)
    h.update(source[0].get_contents())
    fp = open(str(source[0]) +"."+ alg, 'wb')
    fp.write("%s(%s)= %s\n" % (alg.upper(), basename(str(source[0])), h.hexdigest()))
    fp.close()

def generate(env):
  env['HASHFILE_ALGS'] = ['md5', 'sha1', 'ripemd160']
  env.Append(BUILDERS = {
    'HashFile': env.Builder(action = SCons.Action.Action(hashfile, hashfile_string),
                           emitter = hashfile_emitter,
                           target_factory = env.fs.Entry)
                           })

def exists(env):
  try:
    import hashlib
  except ImportError:
    return False
  return True

