#!/usr/bin/env python

# Copyright (c) 2018 Gianluigi Tiesi <sherpya@netfarm.it>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

import sys
import os
from ctypes import *
from ctypes.util import find_library

__author__ = 'Gianluigi Tiesi'
__email__ = 'sherpya@netfarm.it'
__version__ = '0.99.4'


cl_engine_p = c_void_p
c_int_p = POINTER(c_int)
c_uint_p = POINTER(c_uint)
c_ulong_p = POINTER(c_ulong)
c_char_pp = POINTER(c_char_p)

try:
    library = find_library('clamav') or find_library('libclamav') or 'libclamav'
    libclamav = cdll[library]
except Exception:
    print 'Unable to load libclamav library, make sure it is in search path\n'
    raise

libclamav.cl_init.argtypes = (c_uint,)
libclamav.cl_retdbdir.restype = c_int

libclamav.cl_retdbdir.argtypes = None
libclamav.cl_retdbdir.restype = c_char_p

libclamav.cl_debug.argtypes = None
libclamav.cl_debug.restype = None

libclamav.cl_strerror.argtypes = (c_int,)
libclamav.cl_strerror.restype = c_char_p

libclamav.cl_initialize_crypto.argtypes = None
libclamav.cl_initialize_crypto.restype = c_int
libclamav.cl_initialize_crypto()

libclamav.cl_engine_new.argtypes = None
libclamav.cl_engine_new.restype = cl_engine_p

libclamav.cl_engine_free.argtypes = (cl_engine_p,)
libclamav.cl_engine_free.restype = c_int

libclamav.cl_load.argtypes = (c_char_p, cl_engine_p, c_uint_p, c_uint)
libclamav.cl_load.restype = c_int

libclamav.cl_engine_compile.argtypes = (cl_engine_p,)
libclamav.cl_engine_compile.restype = c_int

libclamav.cl_retver.argtypes = None
libclamav.cl_retver.restype = c_char_p


# noinspection PyPep8Naming
class cl_stat(Structure):
    _fields_ = [
        ('dir', c_char_p),
        ('stattab', c_void_p),
        ('statdname', c_char_pp),
        ('entries', c_uint)
    ]


cl_stat_p = POINTER(cl_stat)

libclamav.cl_statinidir.argtypes = (c_char_p, cl_stat_p)
libclamav.cl_statinidir.restype = c_int

libclamav.cl_statfree.argtypes = (cl_stat_p,)
libclamav.cl_statfree.restype = c_int

libclamav.cl_statchkdir.argtypes = (cl_stat_p,)
libclamav.cl_statchkdir.restype = c_int


# noinspection PyPep8Naming
class cl_cvd(Structure):
    _fields_ = [
        ('time', c_char_p),
        ('version', c_uint),
        ('sigs', c_uint),
        ('fl', c_uint),
        ('md5', c_char_p),
        ('dsig', c_char_p),
        ('builder', c_char_p),
        ('stime', c_uint)
    ]


cl_cvd_p = POINTER(cl_cvd)

libclamav.cl_cvdhead.argtypes = (c_char_p,)
libclamav.cl_cvdhead.restype = cl_cvd_p

libclamav.cl_cvdfree.argtypes = (cl_cvd_p,)
libclamav.cl_cvdfree.restype = None

libclamav.cl_scanfile.argtypes = (c_char_p, c_char_pp, c_ulong_p, cl_engine_p, c_uint)
libclamav.cl_scanfile.restype = c_int

CL_CLEAN = 0,
CL_SUCCESS, \
    CL_VIRUS, \
    CL_ENULLARG, \
    CL_EARG, \
    CL_EMALFDB, \
    CL_ECVD, \
    CL_EVERIFY, \
    CL_EUNPACK, \
    CL_EOPEN, \
    CL_ECREAT, \
    CL_EUNLINK, \
    CL_ESTAT, \
    CL_EREAD, \
    CL_ESEEK, \
    CL_EWRITE, \
    CL_EDUP, \
    CL_EACCES, \
    CL_ETMPFILE, \
    CL_ETMPDIR, \
    CL_EMAP, \
    CL_EMEM, \
    CL_ETIMEOUT, \
    CL_BREAK, \
    CL_EMAXREC, \
    CL_EMAXSIZE, \
    CL_EMAXFILES, \
    CL_EFORMAT, \
    CL_EPARSE, \
    CL_EBYTECODE, \
    CL_EBYTECODE_TESTFAIL, \
    CL_ELOCK, \
    CL_EBUSY, \
    CL_ESTATE, \
    CL_ELAST_ERROR = range(34)

is_clamwin = False

# helpers used by clamwin
if sys.platform == 'win32':
    try:
        IsWow64Process = windll.kernel32.IsWow64Process
        IsWow64Process.argtypes = (c_void_p, POINTER(c_int))
        IsWow64Process.restypes = c_int
        GetCurrentProcess = windll.kernel32.GetCurrentProcess
        GetCurrentProcess.argtypes = None
        GetCurrentProcess.restype = c_void_p
    except AttributeError:
        def isWow64():
            return False
    else:
        def isWow64():
            is_wow64 = c_int()
            IsWow64Process(GetCurrentProcess(), byref(is_wow64))
            return bool(is_wow64)

    try:
        libclamav.cw_disablefsredir.argtypes = None
        libclamav.cw_disablefsredir.restypes = c_int
        libclamav.cw_revertfsredir.argtypes = None
        libclamav.cw_revertfsredir.restypes = c_int

        def disableFsRedir():
            return bool(libclamav.cw_disablefsredir())

        def revertFsRedir():
            return bool(libclamav.cw_revertfsredir())

        is_clamwin = True
    except AttributeError:
        def disableFsRedir():
            return False
        revertFsRedir = disableFsRedir


def clStrError(error):
    return str(libclamav.cl_strerror(error))


class ClamavException(Exception):
    pass


res = libclamav.cl_init(0)
if res != CL_SUCCESS:
    raise ClamavException(clStrError(res))
del res


class Scanner(object):
    __slots__ = ['dbpath', 'autoreload', 'dbstats', 'engine', 'signo', 'dboptions']

    DBNAMES = ('main', 'daily', 'bytecode')

    libclamav = libclamav
    dbstats = cl_stat()
    dbstats_p = byref(dbstats)

    def __init__(self, dbpath=None, autoreload=False, debug=False):
        if dbpath is None:
            dbpath = str(libclamav.cl_retdbdir())
        self.dbpath = dbpath
        self.autoreload = autoreload
        self.engine = None

        if dbpath is None or not os.path.isdir(dbpath):
            raise ClamavException('Invalid database path')

        if debug:
            self.libclamav.cl_debug()

        self.signo = c_uint()
        self.dboptions = 0

    def __del__(self):
        if self.dbstats.entries:
            self.libclamav.cl_statfree(self.dbstats_p)
        if self.engine:
            self.libclamav.cl_engine_free(self.engine)

    def cl(self, func, *args):
        ret = func(*args)
        if ret != CL_SUCCESS:
            raise ClamavException(self.libclamav.cl_strerror(ret))

    def loadDB(self):
        if self.dbstats.entries:
            self.cl(self.libclamav.cl_statfree, self.dbstats_p)

        if self.engine:
            self.cl(self.libclamav.cl_engine_free, self.engine)

        self.engine = libclamav.cl_engine_new()
        if not self.engine:
            raise ClamavException('cl_engine_new() failed')

        self.cl(self.libclamav.cl_statinidir, self.dbpath, self.dbstats_p)
        self.cl(self.libclamav.cl_load, self.dbpath, self.engine, byref(self.signo), self.dboptions)
        self.cl(self.libclamav.cl_engine_compile, self.engine)

    def checkAndLoadDB(self):
        if not self.engine:
            return self.loadDB()

        ret = self.libclamav.cl_statchkdir(self.dbstats_p)
        if ret == CL_SUCCESS:
            pass
        elif ret == 1:
            self.loadDB()
        else:
            raise ClamavException(self.libclamav.cl_strerror(ret))

    def scanFile(self, filename):
        if self.autoreload:
            self.checkAndLoadDB()
        if not self.engine:
            raise ClamavException('No database loaded')

        virname = c_char_p()
        scanned = c_ulong()
        ret = self.libclamav.cl_scanfile(filename, byref(virname), byref(scanned), self.engine, 0)
        return ret, virname.value, scanned.value

    def getVersions(self):
        versions = {
            'clamav': self.libclamav.cl_retver()
        }
        for dbname in Scanner.DBNAMES:
            dbpath = os.path.join(self.dbpath, dbname + '.cvd')
            if not os.path.isfile(dbpath):
                dbpath = os.path.join(self.dbpath, dbname + '.cld')
            if not os.path.isfile(dbpath):
                continue
            cvd = self.libclamav.cl_cvdhead(dbpath)
            if cvd:
                versions[dbname] = cvd.contents.version
                self.libclamav.cl_cvdfree(cvd)
            else:
                versions[dbname] = 0

        return versions


if __name__ == '__main__':
    scanner = Scanner(autoreload=True)
    print scanner.signo.value
    print scanner.getVersions()
    print scanner.scanFile('clam.exe')
