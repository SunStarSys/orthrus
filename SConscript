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

# Everything that gets built, in dependency order.  The SConstruct reads this
# through a single VariantDir, so the child SConscripts below inherit it and
# must not declare variant dirs of their own.
#
# The SConstruct owns configuration, installation and packaging; this file
# and its children own "what gets compiled".

from os.path import join as pjoin

Import('env', 'VERSION', 'BUILD_DIR')

libinfo = SConscript(pjoin('src', 'SConscript'),
                     exports={'env': env,
                              'VERSION': VERSION,
                              'BUILD_DIR': BUILD_DIR})
lib = libinfo['lib']

# Everything downstream links against liborthrus.
appenv = env.Clone()
appenv.AppendUnique(LIBS=lib)
if appenv['PLATFORM'] != 'darwin':
  # TODO: figure out whether the OS supports $ORIGIN-relative rpaths, which
  # would let an installed binary find the library without an absolute path:
  #   appenv.Append(LINKFLAGS=Split('-z origin'))
  #   appenv.Append(RPATH=env.Literal(pjoin('\\$$ORIGIN', os.pardir, 'lib')))
  # Until then, point at the install prefix.
  appenv.Append(RPATH=[pjoin(env['PREFIX'], 'lib')])

uiinfo = SConscript(pjoin('src', 'ui', 'SConscript'),
                    exports={'env': appenv, 'BUILD_DIR': BUILD_DIR})

testinfo = SConscript(pjoin('src', 'tests', 'SConscript'),
                      exports={'env': appenv, 'BUILD_DIR': BUILD_DIR})

result = {
    'lib': lib,
    'ortcalc': uiinfo['ortcalc'],
    'ortpasswd': uiinfo['ortpasswd'],
    'otp_sha1': uiinfo['otp_sha1'],
    'pam': uiinfo['pam'],
    'tests': testinfo['tests'],
    # Real (non-variant) paths to every compiled source, for the tarball.
    'dist_sources': (libinfo['dist_sources'] +
                     uiinfo['dist_sources'] +
                     testinfo['dist_sources']),
}

Return('result')
