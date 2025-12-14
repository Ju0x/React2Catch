# React2Catch

A simple honeypot which passively logs any attempt to exploit React2Shell.

## Setup

> **[You can download the latest release.](https://github.com/Ju0x/React2Catch/releases/latest)**

Adding execute permissions:
```
chmod +x react2catch-linux-amd64
```

Running React2Catch:
```
./react2catch-linux-amd64
```

You might also want to use the command line options, depending on your setup:
```
./react2catch-linux-amd64 --addr :1337 --trusted 127.0.0.1,::1 --output ./logs/react2catch.jsonl
```

### --addr
Sets the address to listen on. (e.g. :8080, localhost:1337, ...)
### **--trusted**
Adds trusted IPs which will be accepted for `X-Forwarded-For` or `X-Real-IP` headers, if you're using a Reverse-Proxy

### --output
Sets the output file for the log. (Default: catches.jsonl)

## Build

To build from source, you need an installation of the [Go language](https://go.dev/). It's tested on version 1.25.5, but other versions might also work well.
If you installed go, you can clone the project:
```
git clone https://github.com/Ju0x/React2Catch
```

And build it:
```
go build .
```
