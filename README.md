##What is runtime_lsan
This is a version of the LeakSanitizer (lsan) library from the clang compiler which can be built completely standalone and used with both clang and gcc.

The *embedded\_backtrace* branch also builds libbacktrace from gcc into the resulting library. This allows to use *runtime_lsan* with older versions of GCC and clang.

## What was changed
Original LeakSanitizer in clang has two shorcomings:

* __lsan::DoLeakCheck() function can be only called once during the application runtime, subsequent calls are a no-op which does not allow to use LeakSanitizer to dynamically inspect leak statistics
* LeakSanitizer has little (according to GCC developers, around 20%) performance overhead and in some situations one may want to disable leak detection until they are sure a leak exists and needs detection

To work around these issues, the following modifications were done:

* The limitation on the number of invocations of __lsan::DoLeakCheck() was removed
* Two new functions were provided to enable or disable leak detection. Internally, lsan keeps a table of function pointers and depending on whether interceptors are requested to be enabled or disabled it assigns them either to a local (to lsan) hook or a function from libc (or any other library that is next to lsan in the load order).

## How to build
To build *runtime_lsan* you need to use CMake. For faster builds, you can use the ninja build system instead of make.

### Cleaning up
```
rm -rf build.ninja rules.ninja CMakeFiles *so Makefile CMakeCache.txt cmake_install.cmake \.ninja* 
```

### Building

```
cmake -G Ninja -DBUILD_SHARED_LIBS:BOOL=ON .
ninja
ninja install
```

## How to use
You can either link your application against liblsan.a or load the library dynamically via *LD_PRELOAD* as shown below:
```
LD_PRELOAD=/usr/local/lib/liblsan.so ./my_app
```

The following functions are available and can be obtained from the library via dlsym().

```
void __lsan_do_leak_check(void);
void __lsan_enable_interceptors(void);
void __lsan_disable_interceptors(void);

```
