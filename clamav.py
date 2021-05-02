#!/usr/bin/env python

# Copyright (c) 2018-2021 Gianluigi Tiesi <sherpya@netfarm.it>
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
__version__ = '0.101.0'


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

libclamav.cl_engine_set_num.argtypes = (cl_engine_p, c_int, c_longlong)
libclamav.cl_engine_set_num.restype = c_int

libclamav.cl_engine_get_num.argtypes = (cl_engine_p, c_int, c_int_p)
libclamav.cl_engine_get_num.restype = c_longlong

libclamav.cl_engine_set_str.argtypes = (cl_engine_p, c_int, c_char_p)
libclamav.cl_engine_set_str.restype = c_int

libclamav.cl_engine_get_str.argtypes = (cl_engine_p, c_int, c_int_p)
libclamav.cl_engine_get_str.restype = c_char_p

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


# noinspection PyPep8Naming
class cl_scan_options(Structure):
    _fields_ = [
        ('general', c_uint),
        ('parse', c_uint),
        ('heuristic', c_uint),
        ('mail', c_uint),
        ('dev', c_uint),
    ]


cl_scan_options_p = POINTER(cl_scan_options)

libclamav.cl_retflevel.argtypes = None
libclamav.cl_retflevel.restype = c_uint

libclamav.cl_scanfile.restype = c_int
if libclamav.cl_retflevel() < 101:
    def scanoptions():
        return 0
    libclamav.cl_scanfile.argtypes = (c_char_p, c_char_pp, c_ulong_p, cl_engine_p, c_uint)
else:
    def scanoptions():
        return byref(cl_scan_options(parse=c_uint(~0)))
    libclamav.cl_scanfile.argtypes = (c_char_p, c_char_pp, c_ulong_p, cl_engine_p, cl_scan_options_p)


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

CL_DB_PHISHING = 0x2
CL_DB_PHISHING_URLS = 0x8
CL_DB_PUA = 0x10
CL_DB_PUA_MODE = 0x80
CL_DB_PUA_INCLUDE = 0x100
CL_DB_PUA_EXCLUDE = 0x200
CL_DB_OFFICIAL_ONLY = 0x1000
CL_DB_BYTECODE = 0x2000
CL_DB_BYTECODE_STATS = 0x20000
CL_DB_ENHANCED = 0x40000
CL_DB_PCRE_STATS = 0x80000
CL_DB_YARA_EXCLUDE = 0x100000
CL_DB_YARA_ONLY = 0x200000

CL_DB_STDOPT = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE

CL_ENGINE_MAX_SCANSIZE, \
    CL_ENGINE_MAX_FILESIZE, \
    CL_ENGINE_MAX_RECURSION, \
    CL_ENGINE_MAX_FILES, \
    CL_ENGINE_MIN_CC_COUNT, \
    CL_ENGINE_MIN_SSN_COUNT, \
    CL_ENGINE_PUA_CATEGORIES, \
    CL_ENGINE_DB_OPTIONS, \
    CL_ENGINE_DB_VERSION, \
    CL_ENGINE_DB_TIME, \
    CL_ENGINE_AC_ONLY, \
    CL_ENGINE_AC_MINDEPTH, \
    CL_ENGINE_AC_MAXDEPTH, \
    CL_ENGINE_TMPDIR, \
    CL_ENGINE_KEEPTMP, \
    CL_ENGINE_BYTECODE_SECURITY, \
    CL_ENGINE_BYTECODE_TIMEOUT, \
    CL_ENGINE_BYTECODE_MODE, \
    CL_ENGINE_MAX_EMBEDDEDPE, \
    CL_ENGINE_MAX_HTMLNORMALIZE, \
    CL_ENGINE_MAX_HTMLNOTAGS, \
    CL_ENGINE_MAX_SCRIPTNORMALIZE, \
    CL_ENGINE_MAX_ZIPTYPERCG, \
    CL_ENGINE_FORCETODISK, \
    CL_ENGINE_DISABLE_CACHE, \
    CL_ENGINE_DISABLE_PE_STATS, \
    CL_ENGINE_STATS_TIMEOUT, \
    CL_ENGINE_MAX_PARTITIONS, \
    CL_ENGINE_MAX_ICONSPE, \
    CL_ENGINE_MAX_RECHWP3, \
    CL_ENGINE_MAX_SCANTIME, \
    CL_ENGINE_PCRE_MATCH_LIMIT, \
    CL_ENGINE_PCRE_RECMATCH_LIMIT, \
    CL_ENGINE_PCRE_MAX_FILESIZE, \
    CL_ENGINE_DISABLE_PE_CERTS, \
    CL_ENGINE_PE_DUMPCERTS = range(36)

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


class ClamavException(Exception):
    def __init__(self, message):
        if isinstance(message, int):
            message = str(libclamav.cl_strerror(message))
        Exception.__init__(self, message)


res = libclamav.cl_init(0)
if res != CL_SUCCESS:
    raise ClamavException(res)
del res


def def_engine_options():
    return {
        CL_ENGINE_MAX_SCANSIZE: 1048576 * 50,
        CL_ENGINE_MAX_FILESIZE: 1048576 * 50,
        CL_ENGINE_MAX_FILES: 500,
        CL_ENGINE_MAX_RECURSION: 20
    }


def clfunc(func):
    def wrapper(_, *args, **kwargs):
        raise_on_fail = kwargs.get('raise_on_fail', True)
        ret = func(*args)
        if raise_on_fail and (ret != CL_SUCCESS):
            raise ClamavException(ret)
        return ret
    return wrapper


class Scanner(object):
    DBNAMES = ('main', 'daily', 'bytecode')

    dbstats = cl_stat()
    dbstats_p = byref(dbstats)
    signo = c_uint()
    engine = None

    cl_statfree = clfunc(libclamav.cl_statfree)
    cl_engine_free = clfunc(libclamav.cl_engine_free)
    cl_statinidir = clfunc(libclamav.cl_statinidir)
    cl_load = clfunc(libclamav.cl_load)
    cl_engine_compile = clfunc(libclamav.cl_engine_compile)
    cl_engine_set_num = clfunc(libclamav.cl_engine_set_num)
    cl_engine_set_str = clfunc(libclamav.cl_engine_set_str)
    cl_statchkdir = libclamav.cl_statchkdir
    cl_debug = libclamav.cl_debug
    cl_engine_new = libclamav.cl_engine_new
    cl_scanfile = libclamav.cl_scanfile
    cl_retver = libclamav.cl_retver
    cl_cvdhead = libclamav.cl_cvdhead
    cl_cvdfree = libclamav.cl_cvdfree

    def cl_retdbdir(self):
        return str(libclamav.cl_retdbdir)

    def __init__(self, dbpath=None, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None, debug=False):
        if dbpath is None:
            dbpath = str(libclamav.cl_retdbdir())
        self.dbpath = dbpath
        self.autoreload = autoreload

        self.engine_options = engine_options or def_engine_options()

        if dbpath is None or not os.path.isdir(dbpath):
            raise ClamavException('Invalid database path')

        self.dboptions = dboptions

        if debug:
            self.cl_debug()

    def __del__(self):
        if self.dbstats.entries:
            self.cl_statfree(self.dbstats_p, raise_on_fail=False)
        if self.engine:
            self.cl_engine_free(self.engine, raise_on_fail=False)

    def setEngineOption(self, opt, value):
        if not isinstance(value, (int, str)):
            raise ClamavException('Invalid option value type %s: %r' % (type(value), value))
        self.engine_options[opt] = value

    def setEngineOptions(self, options):
        for opt, value in options.items():
            self.setEngineOption(opt, value)

    def loadDB(self):
        if self.dbstats.entries:
            self.cl_statfree(self.dbstats_p)

        if self.engine is not None:
            self.cl_engine_free(self.engine)

        self.engine = self.cl_engine_new()
        if self.engine is None:
            raise ClamavException('cl_engine_new() failed')

        self.cl_statinidir(self.dbpath, self.dbstats_p)

        for opt, value in self.engine_options.items():
            if isinstance(value, int):
                self.cl_engine_set_num(self.engine, opt, value)
            elif isinstance(value, str):
                self.cl_engine_set_str(self.engine, opt, value)
            else:
                raise ClamavException('Invalid option value type %s: %r' % (type(value), value))

        self.cl_load(self.dbpath, self.engine, byref(self.signo), self.dboptions)
        self.cl_engine_compile(self.engine)

    def checkAndLoadDB(self):
        if not self.engine:
            return self.loadDB()

        ret = self.cl_statchkdir(self.dbstats_p)

        if ret == 0:  # No change
            pass
        elif ret == 1:  # Some change occurred
            self.loadDB()
        else:
            raise ClamavException(ret)

    def scanFile(self, filename):
        if self.autoreload:
            self.checkAndLoadDB()
        if self.engine is None:
            raise ClamavException('No database loaded')

        virname = c_char_p()
        ret = self.cl_scanfile(filename, byref(virname), None, self.engine, scanoptions())
        return ret, virname.value

    def getVersions(self):
        versions = {
            'clamav': self.cl_retver()
        }

        for dbname in Scanner.DBNAMES:
            dbpath = os.path.join(self.dbpath, dbname + '.cvd')
            if not os.path.isfile(dbpath):
                dbpath = os.path.join(self.dbpath, dbname + '.cld')
            if not os.path.isfile(dbpath):
                continue

            cvd = self.cl_cvdhead(dbpath)
            if cvd:
                versions[dbname] = cvd.contents.version
                self.cl_cvdfree(cvd)
            else:
                versions[dbname] = 0

        return versions


if __name__ == '__main__':
    import tempfile
    scanner = Scanner(autoreload=True)
    scanner.setEngineOption(CL_ENGINE_TMPDIR, tempfile.gettempdir())
    print scanner.scanFile('clam.exe')
    print scanner.scanFile('clam.zip')
    print scanner.signo.value
    print scanner.getVersions()
