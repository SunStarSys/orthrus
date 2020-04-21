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

EnsureSConsVersion(1, 2, 0)

import re
import os
from os.path import join as pjoin
from os.path import dirname

opts = Variables('build.py', ARGUMENTS)

def read_version(prefix, path):
  version_re = re.compile("(.*)%s_(?P<id>MAJOR|MINOR|PATCH)_VERSION(\s+)(?P<num>\d)(.*)" % prefix)
  versions = {}
  fp = open(path, 'rb')
  for line in fp.readlines():
    m = version_re.match(line.decode("utf-8"))
    if m:
      versions[m.group('id')] = int(m.group('num'))
  fp.close()
  return (versions['MAJOR'], versions['MINOR'], versions['PATCH'])

# From: http://www.scons.org/wiki/AutoconfRecipes?
def checkEndian(context):
    context.Message("Checking Endianess ... ")
    import struct
    array = struct.pack('cccc', b'\x01', b'\x02', b'\x03', b'\x04')
    i = struct.unpack('i', array)
    # Little Endian
    if i == struct.unpack('<i', array):
        context.Result("little")
        return "little"
    # Big Endian
    elif i == struct.unpack('>i', array):
        context.Result("big")
        return "big"
    context.Result("unknown")
    return "unknown"

def check_vasprintf(context):
    context.Message("Checking for vasprintf ... ")
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

orthrus_major, orthrus_minor, orthrus_patch = read_version('ORTHRUS', 'include/orthrus_version.h')
orthrus_vstring = "%d.%d.%d"  % (orthrus_major, orthrus_minor, orthrus_patch)

opts.Add(PathVariable('PREFIX', 'Prefix of where to install', '/usr/local', validator=PathVariable.PathAccept))
opts.Add(PathVariable('DESTDIR', 'Prefix for packaging purposes', '/', validator=PathVariable.PathAccept))
opts.Add(PathVariable('APR', 'Path to apr-1-config',
    WhereIs('apr-1-config') or '/usr/local/bin/apr-1-config', validator=PathVariable.PathIsFile))
opts.Add(PathVariable('APRUTIL', 'Path apu-1-config',
    WhereIs('apu-1-config') or '/usr/local/bin/apu-1-config', validator=PathVariable.PathIsFile))

opts.Add(BoolVariable('DEBUG', 'Compile in debug mode', True))

env = Environment(options=opts, tools=['default', 'packaging', 'hashfile'])

env.ParseConfig(env['APR'] + ' --cflags --cppflags --includes --libs --ldflags --link-ld')
env.ParseConfig(env['APRUTIL'] + ' --includes  --ldflags  --libs --link-ld')
env.AppendUnique(CPPPATH = ["include"])
libsource = ['src/core.c', 'src/error.c',
                                  'src/hex.c', 'src/words.c',
                                  'src/md4.c', 'src/md5.c', 'src/sha1.c',
                                  'src/userdb.c']

lib = env.SharedLibrary(target='orthrus-%d' % (orthrus_major),
                        source = libsource)

headers = env.Glob('include/*.h')
headers.append(env.File('include/private/context.h'))

conf = env.Configure(config_h='include/private/config.h', custom_tests = { 'CheckEndian' : checkEndian, 'CheckVasprintf': check_vasprintf })

cc = conf.env.WhereIs('clang') or conf.env.WhereIs('/Developer/usr/bin/clang')
if 'CC' in os.environ:
  cc = os.environ['CC']
if cc:
  conf.env['CC'] = cc

conf.CheckCHeader("security/pam_modules.h")
conf.CheckCHeader("pam/pam_modules.h")
conf.CheckCHeader("security/pam_appl.h")
conf.CheckCHeader("pam/pam_appl.h")

if conf.CheckEndian() == "big":
  conf.env.AppendUnique(CPPFLAGS=['-DBIGENDIAN'])

if conf.CheckVasprintf():
  conf.env.AppendUnique(CPPFLAGS=['-DHAVE_VASPRINTF'])

if conf.CheckDeclaration("__GNUC__"):
  conf.env['HAVE_GCC_LIKE'] = True
else:
  conf.env['HAVE_GCC_LIKE'] = False

env = conf.Finish()

if env['DEBUG']:
  env.AppendUnique(CFLAGS=['-O0'])
  if env['HAVE_GCC_LIKE']:
    env.AppendUnique(CFLAGS=['-ggdb'])
else:
  env.AppendUnique(CFLAGS=['-O2'])

if env['HAVE_GCC_LIKE']:
  env.AppendUnique(CFLAGS=['-Wall'])

env.AppendUnique(RPATH = env['LIBPATH'])

appenv = env.Clone()
appenv.AppendUnique(LIBS=lib)
if appenv['PLATFORM'] != 'darwin':
  if 0:
    # TOOD: Figure out if OS supports origin/relative rpaths
    appenv.Append(LINKFLAGS = Split('-z origin'))
    appenv.Append(RPATH = env.Literal(pjoin('\\$$ORIGIN', os.pardir, 'lib')))
  else:
    appenv.Append(RPATH = [pjoin(env['PREFIX'], 'lib')])


tests = appenv.Program(target='orthrustest', source = ['src/tests/orthrustest.c'])
ortcalc = appenv.Program(target='ortcalc', source = ['src/ui/ortcalc/ortcalc.c'])
ortpasswd = appenv.Program(target='ortpasswd', source = ['src/ui/ortpasswd/ortpasswd.c'])

pamenv = appenv.Clone()
pamenv.AppendUnique(LIBS='pam')
pamorthrus = pamenv.LoadableModule(target = "pam_orthrus.so",
                                   source = ['src/ui/pam/pam_orthrus.c'], SHLIBPREFIX='')


install = []
def edit_path(env, obj):
  if env['PLATFORM'] == 'darwin':
    env.AddPostAction(obj,
      "install_name_tool -change 'liborthrus-%d.dylib' '%s/liborthrus-%d.dylib' %s" % (orthrus_major,
        pjoin(env['PREFIX'], 'lib'), orthrus_major, obj[0].get_abspath()))
  return obj

def hack_fileperms(env, obj):
  env.AddPostAction(obj, "chmod u+s '%s'" % obj[0].get_abspath())
  return obj

install.extend(edit_path(env, env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'bin'), ortcalc)))
install.extend(hack_fileperms(env, edit_path(env, env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'bin'), ortpasswd))))
install.extend(env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'lib'), lib))

#
# TODO: Figure out a better test, how do you know if it uses 'pam' or 'security'
# for the directory name.
if env['PLATFORM'] == 'darwin':
  install.extend(edit_path(env, env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'lib', 'pam'), pamorthrus)))
else:
  install.extend(env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'lib', 'security'), pamorthrus))

install.extend(env.Install(pjoin(env['DESTDIR'], env['PREFIX'], 'include', "orthrus-%d" % (orthrus_major)), headers))

# Creating a release tarball
name = "orthrus-%d.%d.%d" % (orthrus_major, orthrus_minor, orthrus_patch)

files = []
files.extend(['LICENSE','README', 'TODO','NOTICE','SConstruct'])
files.extend(env.Glob("site_scons/site_tools/*.py"))
files.extend(env.Glob("site_scons/*.py"))
files.extend(env.FindSourceFiles('src'))
files.extend(headers)

packaging = {'NAME': 'orthrus',
'VERSION':          orthrus_vstring,
'PACKAGEVERSION':  0,
'PACKAGETYPE':     'src_tarbz2',
'LICENSE':         'Apache 2.0',
'SUMMARY':        'A one time password system',
'DESCRIPTION':    'Orthrus is a C library and user interfaces for RFC 2289, "A One-Time Password System (OTP)", also known as OPIE or S/Key.',
'X_RPM_GROUP':    'Productivity/Security',
'source': files
}

dist = []
tb = env.Package(**packaging)
dist.extend([tb, env.HashFile(tb)])

packaging['PACKAGETYPE'] = 'src_targz'
tb = env.Package(**packaging)
dist.extend([tb, env.HashFile(tb)])

hasrpm = env.WhereIs('rpmbuild')
if hasrpm:
  packaging['PACKAGETYPE'] = 'rpm'
  del packaging['source'];
  rpm = env.Package(**packaging)


targets = [lib, pamorthrus, ortcalc, ortpasswd, tests]
env.Alias('install', install)
env.Alias('dist', dist)
if hasrpm:
  env.Alias('rpm', rpm)
env.Clean('dist', dist)
test_alias = env.Alias('test', [tests], tests[0].get_abspath())
AlwaysBuild(test_alias)

# This can break the Configure context a little too easily, leave it out until
# a future scons version.
#env.Clean(targets, '.sconf_temp')
env.Default(targets)
