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

"""Reads the project version straight out of the public C header, so the
header stays the single place a version number is written down."""

import collections
import re

PARTS = ('MAJOR', 'MINOR', 'PATCH')


class Version(collections.namedtuple('Version', 'major minor patch')):
  """A (major, minor, patch) triple that stringifies as "0.8.0"."""

  __slots__ = ()

  def __str__(self):
    return '%d.%d.%d' % self


def read_version(prefix, path):
  """Parse ``<PREFIX>_{MAJOR,MINOR,PATCH}_VERSION`` out of the header at path.

  Raises ValueError if the header is missing any of the three, which beats
  letting a half-built version string leak into tarball names.
  """
  pattern = re.compile(
      r'^\s*#\s*define\s+%s_(?P<id>%s)_VERSION\s+(?P<num>\d+)\s*$'
      % (re.escape(prefix), '|'.join(PARTS)))

  versions = {}
  with open(path, 'r') as fp:
    for line in fp:
      m = pattern.match(line)
      if m:
        versions[m.group('id')] = int(m.group('num'))

  missing = [part for part in PARTS if part not in versions]
  if missing:
    raise ValueError('%s defines no %s' % (
        path, ', '.join('%s_%s_VERSION' % (prefix, part) for part in missing)))

  return Version(*(versions[part] for part in PARTS))
