# sss-webserver

A simple, easy-to-use embedded HTTP and HTTPS webserver that determines file MIME types and serves a directory. The server runs on a background thread and lives for as long as it remains in scope.

## Prerequisites
This project requires certain packages to be installed onto the system during the build process. But most are not required during runtime. To see the full list of packages required for building the executable/library, please see the contents of the file [DEPENDENCIES](DEPENDENCIES).

## Usage

### CLI

```bash
# HTTP
sss-webserver /path/to/directory

# HTTPS
sss-webserver -c cert.pem -k key.pem /path/to/directory
```

### C++

```cpp
#include <sss/webserver.hpp>

// HTTP (default port 8080 on 127.0.0.1)
sss::webserver::Server server("/path/to/directory");

// HTTP with custom port and host
sss::webserver::Server server("/path/to/directory", 8080, "127.0.0.1");

// HTTPS
sss::webserver::Server secure_server("/path/to/directory", 8443, "127.0.0.1", "cert.pem", "key.pem");
```
