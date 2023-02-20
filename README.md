# clienthellod
ClientHello Parser/Resolver as a Service from [tlsfingerprint.io](https://tlsfingerprint.io) but in Python 3.

## Note

The ssl module in Python 3 may advertise `pre_shared_key` and result in any subsequent `ClientHello` to have `pre_shared_key` in the extensions list, resulting a different fingerprint. 