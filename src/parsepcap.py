#!/usr/bin/python
import hashlib
import struct

def ungrease_one(a):
    if (a & 0x0f0f) == 0x0a0a and (a & 0xf000) >> 8 == (a & 0x00f0):
        return 0x0a0a
    return a

def ungrease(x):
    return map(ungrease_one, x)

# Could use struct.parse, but meh. want arbitrary length arrays of base-256 data
def aint(arr):
    s = 0
    try:
        iterator = iter(arr)
    except TypeError:
        # not iterable
        s = arr
    else:
        # iterable
        for a in arr:
            s *= 256
            s += a
    return s

# convert lists of u16 to list of u8s
def list_u16_to_u8(l):
    return [u8 for pair in [[u16 >> 8, u16 & 0xff] for u16 in l] for u8 in pair]

def list_u8_to_u16(l):
    return [u16 for u16 in [l[i] << 8 | l[i + 1] for i in range(0, len(l), 2)]]

def normalize_extensions(exts):
        exts_u16 = list_u8_to_u16(exts)
        exts_u16.sort()
        return list_u16_to_u8(exts_u16)

fprints = {}

#convenience function for generating fingerprint
def update_arr(h, arr):
    h.update(struct.pack('>L', len(arr)))
    h.update(bytes(arr))

class Fingerprint:
    def __init__(self, tls_version, ch_version, cipher_suites, comp_methods, extensions,
                 elliptic_curves, ec_point_fmt, sig_algs, alpn,
                 key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs, record_size_limit,
                 sni=""):
        self.tls_version = tls_version
        self.ch_version = ch_version
        self.cipher_suites = cipher_suites
        self.comp_methods = comp_methods
        self.extensions = extensions
        self.extensions_norm = normalize_extensions(extensions)
        self.elliptic_curves = elliptic_curves
        self.ec_point_fmt = ec_point_fmt
        self.sig_algs = sig_algs
        self.alpn = alpn
        self.key_share = key_share
        self.psk_key_exchange_modes = psk_key_exchange_modes
        self.supported_versions = supported_versions
        self.cert_compression_algs = cert_compression_algs
        self.record_size_limit = record_size_limit
        self.id = None
        self.sni = sni

    @staticmethod
    def from_tls_data(tls):
        if len(tls) == 0:
            return None
        if tls[0] != 0x16:
            # Not a handshake
            print(f"Not HS, tls[0]: {tls[0]}")
            return None
        tls_version = aint(tls[1:3])
        tls_len = aint(tls[3:5])
        hs_type = tls[5]
        if hs_type != 0x01:
            # not a client hello
            print(f"Not ClientHello, hs_type: {hs_type}")
            return None

        print("Parsing TLS")

        # Parse client hello
        chello_len = aint(tls[6:9])
        chello_version = aint(tls[9:11])
        rand = tls[11:11 + 32]
        off = 11 + 32

        # session ID
        sess_id_len = aint(tls[off])
        off += 1 + sess_id_len

        # print 'sess_id len %d (off %d)' % (sess_id_len, off)
        # print tls.encode('hex')

        # Cipher suites
        cs_len = aint(tls[off:off + 2])
        off += 2
        x = tls[off:off + cs_len]
        cipher_suites = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in range(int(len(x) / 2))]))
        off += cs_len

        # Compression
        comp_len = aint(tls[off])
        off += 1
        comp_methods = [aint(x) for x in tls[off:off + comp_len]]
        off += comp_len

        # Extensions
        ext_len = aint(tls[off:off + 2])
        off += 2

        sni_host = ''
        curves = []
        pt_fmts = []
        sig_algs = []
        alpn = []
        key_share = []
        psk_key_exchange_modes = []
        supported_versions = []
        cert_comp_algs = []
        record_size_limit = []
        exts = []
        end = off + ext_len
        while off < end:
            ext_type = aint(tls[off:off + 2])
            off += 2
            ext_len = aint(tls[off:off + 2])
            off += 2
            exts.append(ext_type)

            if ext_type == 0x0000:
                # SNI
                sni_len = aint(tls[off:off + 2])
                sni_type = aint(tls[off + 2])
                sni_len2 = aint(tls[off + 3:off + 5])
                sni_host = tls[off + 5:off + 5 + sni_len2].decode('utf-8')

            elif ext_type == 0x000a:
                # Elliptic curves
                # len...

                x = tls[off:off + ext_len]
                curves = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in range(int(len(x) / 2))]))
            elif ext_type == 0x000b:
                # ec_point_fmt
                pt_fmt_len = aint(tls[off])
                pt_fmts = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x000d:
                # sig algs
                # Actually a length field, and actually these are 2-byte pairs but
                # this currently matches format...
                sig_algs = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0010:
                # alpn
                # also has a length field...
                alpn = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0033:
                # key share
                this_ext = tls[off:off+ext_len]
                overall_len = aint(this_ext[0:2])
                groups = []
                idx = 2
                while idx+2 < len(this_ext):
                    # parse the named group
                    group = ungrease_one(aint(this_ext[idx:idx+2]))
                    # skip the next bytes
                    key_len = aint(this_ext[idx+2:idx+4])
                    groups.append(group)
                    groups.append(key_len)
                    idx += 2 + 2 + key_len

                key_share = list_u16_to_u8(groups)
            elif ext_type == 0x002d:
                # psk_key_exchange_modes
                # skip length
                psk_key_exchange_modes = [aint(x) for x in tls[off+1:off+ext_len]]
            elif ext_type == 0x002b:
                # supported_versions
                x = tls[off+1:off+ext_len]   # skip length
                supported_versions = list_u16_to_u8(ungrease([aint(x[2*i:2*i+2]) for i in range(int(len(x)/2))]))
            elif ext_type == 0x001b:
                # compressed_cert
                cert_comp_algs = [aint(x) for x in tls[off:off+ext_len]]
            elif ext_type == 0x001c:
                record_size_limit = [aint(x) for x in tls[off:off+ext_len]]

 

            off += ext_len

        exts = list_u16_to_u8(ungrease(exts))
        return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
                                         exts, curves, pt_fmts, sig_algs, alpn,
                                         key_share, psk_key_exchange_modes, supported_versions,
                                         cert_comp_algs, record_size_limit, sni=sni_host)
        #return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
        #                   exts, curves, pt_fmts, sig_algs, alpn, id, sni=sni_host)


    def get_fingerprint_v2(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)

        update_arr(h, self.key_share)
        update_arr(h, self.psk_key_exchange_modes)
        update_arr(h, self.supported_versions)
        update_arr(h, self.cert_compression_algs)
        update_arr(h, self.record_size_limit)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out

    def get_fingerprint_v1(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out

    def get_fingerprint(self):
        if self.id is None:
            self.id = self.get_fingerprint_v2()
        return self.id

    def get_fingerprint_normalized(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions_norm)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)
        update_arr(h, self.key_share)
        update_arr(h, self.psk_key_exchange_modes)
        update_arr(h, self.supported_versions)
        update_arr(h, self.cert_compression_algs)
        update_arr(h, self.record_size_limit)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out