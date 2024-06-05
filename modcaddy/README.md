# `clienthellod/modcaddy`: clienthellod as a Caddy module


`clienthellod` is also provided as a Caddy plugin, `modcaddy`, which can be used to capture ClientHello messages and QUIC Client Initial Packets. See Section [modcaddy](#modcaddy) for more details.

`modcaddy` contains a Caddy plugin that provides:
- An caddy `app` that can be used to temporarily store captured ClientHello messages and QUIC Client Initial Packets. 
- A caddy `handler` that can be used to serve the ClientHello messages and QUIC Client Initial Packets to the client sending the request. 
- A caddy `listener` that can be used to capture ClientHello messages and QUIC Client Initial Packets.

You will need to use [xcaddy](https://github.com/caddyserver/xcaddy) to rebuild Caddy with `modcaddy` included.

It is worth noting that some web browsers may not choose to switch to QUIC protocol in localhost environment, which may result in the QUIC Client Initial Packet not being sent and therefore not being captured/analyzed.

### Build 

```bash
xcaddy build --with github.com/gaukas/clienthellod/modcaddy
```

#### When build locally with changes 

```bash
xcaddy build --with github.com/gaukas/clienthellod/modcaddy --with github.com/gaukas/clienthellod/=./
```

### Caddyfile

A sample Caddyfile is provided below.

```Caddyfile
{      
    # debug # for debugging purpose
    # https_port   443 # currently, QUIC listener works only on port 443, otherwise you need to make changes to the code
    order clienthellod before file_server # make sure it hits handler before file_server
    clienthellod { # app (reservoir)
        tls_ttl 10s
        quic_ttl 60s
    }
    servers {
        listener_wrappers {
            clienthellod { # listener
                tcp # listens for TCP and saves TLS ClientHello 
                udp # listens for UDP and saves QUIC Client Initial Packet
            }
            tls
        }
        # protocols h3
    }
}

1.mydomain.com {
    # tls internal
    clienthellod { # handler
        # quic # mutually exclusive with tls
        tls # listener_wrappers.clienthellod.tcp must be set
    }
    file_server {
        root /var/www/html
    }
}

2.mydomain.com {
    # tls internal
    clienthellod { # handler
        quic # listener_wrappers.clienthellod.udp must be set
        # tls # mutually exclusive with quic
    }
    file_server {
        root /var/www/html
    }
}
```