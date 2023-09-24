# libnetplus

## Features
- eventpolling
- tcp/udp server and clients connections
- connection pool
- threading support
- ipv4/6 support
- unixsockets

### on work 
- tls support

### todo
- quick support
- kqueue support(bsd)
- iocp support (windows)

## Dependencies
- linux 2.6 upwards
- clang/gcc (cpp14 or higher)
- cmake
- libcryptoplus
- libc (musl and glibc testet)

## Howto build
- cd projectdir
- mkdir build
- cd build
- cmake ../
- make
- make install

