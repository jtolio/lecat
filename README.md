# lecat

socat-lite with letsencrypt support

## Why?

I often find myself running web services on unprivileged ports such as 8000,
8080, etc, and then later decide I want to access these things on port 80.
In these cases, I often run something like
`sudo socat TCP-LISTEN:80,fork,reuseaddr TCP:localhost:8080`. What this does
is start a small process that listens on port 80 and forwards all incoming
connections to my process on port 8080.

Unfortunately, this isn't HTTPS or SSL. It'd be nice to be able to run a small
binary like socat that listens on 443, does SSL termination, and redirects the
actual unencrypted traffic to localhost:8080.

With the advent of [Let's Encrypt](https://letsencrypt.org/), having a small
binary that actually does the entire process of making a key, getting a
valid certificate, and doing the proxying is now possible!

`lecat` is this thing.

## Example Usage

All you gotta do is tell lecat the domain your process is visible from and the
local unencrypted port to forward to.

```
lecat --host your.website.tld --target localhost:8080
```

An example session:

```
$ ./my-unprivileged-thing.py --listen localhost:8080 &
$ go get github.com/jtolds/lecat
$ sudo ~/your/gopath/bin/lecat --host your.website.tld --target localhost:8080
2016/02/07 07:12:25 loading configuration
2016/02/07 07:12:25 no key found at /root/.lecat/server.key, generating
2016/02/07 07:12:35 no cert found at /root/.lecat/server.crt, requesting
2016/02/07 07:12:35 no key found at /root/.lecat/account.key, generating
2016/02/07 07:12:44 (re)registering account key
2016/02/07 07:12:44 getting challenges for "your.website.tld"
2016/02/07 07:12:45 performing sni challenge
2016/02/07 07:12:46 waiting for challenge
2016/02/07 07:12:47 making csr
2016/02/07 07:12:47 getting cert
2016/02/07 07:12:47 listening on [::]:443
```

Running it again will reload existing keys and certificates:

```
$ sudo ~/your/gopath/bin/lecat --host your.website.tld --target localhost:8080
2016/02/07 07:19:13 loading configuration
2016/02/07 07:19:14 listening on [::]:443
```

Lastly, you can also pass `--redirect-addr :80` to have the process start a
small HTTP server listening on port 80 that redirects incoming unencrypted
requests to HTTPS. Be aware that this little HTTP server will set the HSTS
flag on redirected requests for one year, telling incoming browsers to never
try HTTP again for that year period. If you use this setting and this isn't
the behavior that you want, you'll probably need to clear your domain out of
your browser's HSTS database. Or just keep using SSL.

### sudo?

lecat doesn't really need sudo, it just needs
`setcap 'cap_net_bind_service=+ep'` or something. I often
forget the incantation.

## LICENSE

Copyright 2016 JT Olds

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
