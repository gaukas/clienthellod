# `clienthellod/modcaddy`: clienthellod as a Caddy module


`clienthellod` is also provided as a Caddy plugin, `modcaddy`, which can be used to capture ClientHello messages and QUIC Client Initial Packets. See Section [modcaddy](#modcaddy) for more details.

`modcaddy` contains a Caddy plugin that provides:
- An caddy `app` that can be used to temporarily store captured ClientHello messages and QUIC Client Initial Packets. 
- A caddy `handler` that can be used to serve the ClientHello messages and QUIC Client Initial Packets to the client sending the request. 
- A caddy `listener` that can be used to capture ClientHello messages and QUIC Client Initial Packets.

You will need to use [xcaddy](https://github.com/caddyserver/xcaddy) to rebuild Caddy with `modcaddy` included.

It is worth noting that some web browsers may not choose to switch to QUIC protocol in localhost environment, which may result in the QUIC Client Initial Packet not being sent and therefore not being captured/analyzed.

## Build 

```bash
xcaddy build --with github.com/gaukas/clienthellod/modcaddy
```

### When build locally with changes 

```bash
xcaddy build --with github.com/gaukas/clienthellod/modcaddy --with github.com/gaukas/clienthellod/=./
```

## sample Caddyfile

A sample Caddyfile is provided in this directory. 

## Known issues

### QUIC can't be fingerprinted when web browser chooses H2 not H3

Under certain network condition or configurations, a web browser may decide not to switch to QUIC protocol even when the server advertises the support for QUIC. This issue is more likely to happen under the scenarios with low-latency such as in localhost/intranet.

There is no trivial solution to this issue, as there seems to be no way to force the web browser to use QUIC.

### QUIC fingerprint missing for the first request

It is possible that a client sends both H2-over-TCP (TLS) and H3-over-UDP (QUIC) for the first time requesting a web page and decide to render the response from H2-over-TCP (TLS). In this case, the QUIC Client Initial Packet might be not yet recorded. 

Reloading the page might help by fetching the cached QUIC fingerprint if it is captured and not yet expired.

### Fingerprint gone after reloading/refreshing the web page

Some web browsers may decide to reuse the existing unclosed connection for new HTTP requests instead of establishing a new one by sending a new TLS Client Hello or QUIC Initial Packet(s). In which case, no new fingerprint will be captured and if the old fingerprint is expired or otherwise removed, the fingerprint will be gone and nothing will be displayed.

Forcing the web browser to establish a new connection by closing the existing connection, opening a new tab, or use different domain names every time might help. 