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

EnsureSConsVersion(1, 2, 0)

import os
from os.path import join as pjoin

from orthrus.config import CheckEndian, CheckVasprintf, PAM_HEADERS
from orthrus.version import read_version

# Everything the build generates lives under here: object files, the configure
# scratch area and log, the generated config header, and the final binaries.
# Nothing is written back into the source tree.
BUILD_DIR = 'build'

# Object files go one level deeper, so the generated header in BUILD_DIR/include
# stays outside the VariantDir mapping.  Inside it, SCons would also emit the
# directory's source-side counterpart and every compile would carry a duplicate
# -I flag.
VARIANT_DIR = 'build/obj'

VERSION = read_version('ORTHRUS', 'include/orthrus_version.h')


#
# Build variables
#

opts = Variables('build.py', ARGUMENTS)
opts.Add(PathVariable('PREFIX', 'Prefix of where to install', '/usr/local',
                      validator=PathVariable.PathAccept))
opts.Add(PathVariable('DESTDIR', 'Prefix for packaging purposes', '/',
                      validator=PathVariable.PathAccept))
opts.Add(PathVariable('APR', 'Path to apr-1-config',
                      WhereIs('apr-1-config') or '/usr/local/bin/apr-1-config',
                      validator=PathVariable.PathIsFile))
opts.Add(PathVariable('APRUTIL', 'Path to apu-1-config',
                      WhereIs('apu-1-config') or '/usr/local/bin/apu-1-config',
                      validator=PathVariable.PathIsFile))
opts.Add(BoolVariable('DEBUG', 'Compile in debug mode', True))

env = Environment(variables=opts, tools=['default', 'packaging', 'hashfile'])
Help(opts.GenerateHelpText(env))

# Keep the signature database next to the configure cache it refers to.  Left
# at the default (./.sconsign.dblite) it would survive `rm -rf build`, and the
# stale entries make every configure check below report failure -- which shows
# up much later as -DHAVE_VASPRINTF and -Wall quietly vanishing from the
# compile lines, and the PAM module failing to find pam_handle_t.
os.makedirs(BUILD_DIR, exist_ok=True)
env.SConsignFile(pjoin(BUILD_DIR, '.sconsign'))

# $CC wins, then clang wherever we can find it, else whatever SCons detected.
cc = (os.environ.get('CC')
      or env.WhereIs('clang')
      or env.WhereIs('/Developer/usr/bin/clang'))
if cc:
  env['CC'] = cc

# apr-1-config decides it is cross-compiling when argv[0] does not sit under
# the bindir it was configured with, and then prefixes every path it prints
# with argv[0].  Distros ship /bin as a symlink to /usr/bin, so WhereIs() can
# hand back a path that trips exactly that heuristic; realpath avoids it.
env.ParseConfig(os.path.realpath(env['APR']) +
                ' --cflags --cppflags --includes --libs --ldflags --link-ld')
env.ParseConfig(os.path.realpath(env['APRUTIL']) +
                ' --includes --ldflags --libs --link-ld')

# '#' anchors these at the project root; a bare 'include' would resolve
# against each SConscript's variant dir instead.
env.AppendUnique(CPPPATH=['#include', '#%s/include' % BUILD_DIR])


#
# Configure checks
#

conf = env.Configure(
    config_h=pjoin(BUILD_DIR, 'include', 'private', 'config.h'),
    conf_dir=pjoin(BUILD_DIR, '.sconf_temp'),
    log_file=pjoin(BUILD_DIR, 'config.log'),
    custom_tests={
        'CheckEndian': CheckEndian,
        'CheckVasprintf': CheckVasprintf,
    })

# These only populate config.h today -- no source includes it yet, so the PAM
# module is still built unconditionally.  The HAVE_* defines are here for
# whenever src/ui/pam wants to branch on them.
for header in PAM_HEADERS:
  conf.CheckCHeader(header)

if conf.CheckEndian() == 'big':
  conf.env.AppendUnique(CPPFLAGS=['-DBIGENDIAN'])

if conf.CheckVasprintf():
  conf.env.AppendUnique(CPPFLAGS=['-DHAVE_VASPRINTF'])

conf.env['HAVE_GCC_LIKE'] = bool(conf.CheckDeclaration('__GNUC__'))

env = conf.Finish()


#
# Compiler flags
#

if env['DEBUG']:
  env.AppendUnique(CFLAGS=['-O0'])
  if env['HAVE_GCC_LIKE']:
    env.AppendUnique(CFLAGS=['-ggdb'])
else:
  env.AppendUnique(CFLAGS=['-O2'])

if env['HAVE_GCC_LIKE']:
  env.AppendUnique(CFLAGS=['-Wall'])

env.AppendUnique(RPATH=env['LIBPATH'])


#
# Targets
#

# One VariantDir for the whole tree: the root SConscript and its children are
# read as if they lived under BUILD_DIR, so objects are written there while
# duplicate=0 keeps the sources compiled in place.
build = SConscript('SConscript',
                   variant_dir=VARIANT_DIR,
                   duplicate=0,
                   exports={'env': env,
                            'VERSION': VERSION,
                            'BUILD_DIR': BUILD_DIR})

lib = build['lib']
ortcalc = build['ortcalc']
ortpasswd = build['ortpasswd']
otp_sha1 = build['otp_sha1']
pamorthrus = build['pam']
tests = build['tests']

headers = env.Glob('include/*.h')
headers.append(env.File('include/private/context.h'))


#
# Installation
#

def staged(*parts):
  """Join PREFIX-relative parts under DESTDIR.

  PREFIX is absolute, so it has to be made relative first: os.path.join()
  throws away everything before its last absolute component, which silently
  turned DESTDIR into a no-op and installed straight onto the live system.
  """
  prefix = os.path.splitdrive(env['PREFIX'])[1].lstrip(os.sep)
  return pjoin(env['DESTDIR'], prefix, *parts)


bindir = staged('bin')
libdir = staged('lib')
includedir = staged('include', 'orthrus-%d' % VERSION.major)


def edit_path(env, obj):
  """On Darwin the install name is baked in at link time, so rewrite it to
  point at the install prefix."""
  if env['PLATFORM'] == 'darwin':
    env.AddPostAction(obj,
        "install_name_tool -change 'liborthrus-%d.dylib' "
        "'%s/liborthrus-%d.dylib' %s"
        % (VERSION.major, pjoin(env['PREFIX'], 'lib'), VERSION.major,
           obj[0].get_abspath()))
  return obj


def hack_fileperms(env, obj):
  """ortpasswd writes the shared userdb, so it ships setuid."""
  env.AddPostAction(obj, "chmod u+s '%s'" % obj[0].get_abspath())
  return obj


install = []
install.extend(edit_path(env, env.Install(bindir, ortcalc)))
install.extend(edit_path(env, env.Install(bindir, otp_sha1)))
install.extend(hack_fileperms(env, edit_path(env, env.Install(bindir,
                                                              ortpasswd))))
install.extend(env.Install(libdir, lib))

# TODO: figure out a better test; how do you know whether the platform uses
# 'pam' or 'security' for the module directory name?
if env['PLATFORM'] == 'darwin':
  install.extend(edit_path(env, env.Install(pjoin(libdir, 'pam'),
                                            pamorthrus)))
else:
  install.extend(env.Install(pjoin(libdir, 'security'), pamorthrus))

install.extend(env.Install(includedir, headers))


#
# Release tarballs
#

files = [env.File(f) for f in
         ('LICENSE', 'README', 'TODO', 'NOTICE', 'SConstruct', 'SConscript')]
files.extend(env.File(pjoin(d, 'SConscript'))
             for d in ('src', 'src/ui', 'src/tests'))
files.extend(env.Glob('site_scons/*.py'))
files.extend(env.Glob('site_scons/orthrus/*.py'))
files.extend(env.Glob('site_scons/site_tools/*.py'))
files.extend(build['dist_sources'])
files.extend(headers)

packaging = {
    'NAME': 'orthrus',
    'VERSION': str(VERSION),
    'PACKAGEVERSION': 0,
    'PACKAGETYPE': 'src_tarbz2',
    'LICENSE': 'Apache 2.0',
    'SUMMARY': 'A one time password system',
    'DESCRIPTION': 'Orthrus is a C library and user interfaces for RFC 2289, '
                   '"A One-Time Password System (OTP)", also known as OPIE '
                   'or S/Key.',
    'X_RPM_GROUP': 'Productivity/Security',
    'source': files,
}

dist = []
for packagetype in ('src_tarbz2', 'src_targz'):
  packaging['PACKAGETYPE'] = packagetype
  tarball = env.Package(**packaging)
  dist.extend([tarball, env.HashFile(tarball)])

hasrpm = env.WhereIs('rpmbuild')
if hasrpm:
  packaging['PACKAGETYPE'] = 'rpm'
  del packaging['source']
  rpm = env.Package(**packaging)


#
# Aliases
#

targets = [lib, pamorthrus, ortcalc, ortpasswd, tests, otp_sha1]

env.Alias('install', install)
env.Alias('dist', dist)
if hasrpm:
  env.Alias('rpm', rpm)
env.Clean('dist', dist)

test_alias = env.Alias('test', [tests], tests[0].get_abspath())
AlwaysBuild(test_alias)

env.Default(targets)
