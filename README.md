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

// HTTP
sss::webserver::Options options;
options.port = 8080;
sss::webserver::Server server("/path/to/directory", options);

// HTTPS
sss::webserver::Options https_options;
https_options.port = 8443;
https_options.certificate_path = "cert.pem";
https_options.private_key_path = "key.pem";
sss::webserver::Server secure_server("/path/to/directory", https_options);
```
