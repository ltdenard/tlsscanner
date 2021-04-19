# tweaks to wafw00f to make it work
```
cp main.py ~/path/to/virtenv/lib/python3.9/site-packages/wafw00f/main.py
```
# compiling sslscan
```
git clone https://github.com/rbsec/sslscan.git
cd sslscan
make static
```

# running the whole suite
```
from tlsscanner import TLSScan
tmp_uuid = "688fdb0d-93f6-45ea-a4e4-348f0221670c"
tmp_domain = "example.com"
obj = TLSScan(tmp_uuid, tmp_domain)
obj.scan_domains()
```

# settings up build server
```
yum install zlib-devel.x86_64 python36-virtualenv git
```