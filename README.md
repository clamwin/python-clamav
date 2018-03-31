# pure python ClamAV scanner

It uses ctypes, you need libclamav in your search path.

The usage is simple:

```pycon
>>> import clamav
>>> scanner = clamav.Scanner()
>>> scanner.loadDB()
>>> scanner.scanFile('clam.exe')
(1, 'Clamav.Test.File-6')
```

the resulting tuple is:

* 0 is clamav.CL_CLEAN
* 1 is clamav.CL_VIRUS

the second value is the virus name or None if the file is not infected

You can pass a different database path (rather than the default of the platform) as first argument of the `Scanner` constructor.

If you pass the optional keyword argument `autoreload=True` to the `Scanner` constructor, you don't need to care about loading, reloading database, it check if your db is changed or not loaded, then reloads it.