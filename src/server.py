import argparse
import dpkt
import json
import socket, ssl, struct, sys
import threading, time

from parsepcap import Fingerprint
from prod import db
from http.server import BaseHTTPRequestHandler
from io import BytesIO

chello_lock = threading.RLock()
chello_map = {}  #(addr,port) => (time, client_hello)
psql = db.PSQL()

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message, next):
        self.error_code = code
        self.error_message = message
        print("Error: code {}, message {}, next {}".format(code, message, next))

def cleanup_map(v: bool = False):
    global chello_lock, chello_map
    with chello_lock:
        for client in list(chello_map):
            if chello_map[client][0] < (time.time() - 30):
                if v:
                    print(f'Removing {client}')
                del chello_map[client]

def parse_ip_pkt(ip, port, v: bool = False):
    global chello_lock, chello_map
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    tcp = ip.data
    if tcp.dport != port:
        return

    # Look for client hello
    tls = tcp.data
    if len(tls) == 0:
        return

    if tls[0] != 0x16:
        # Not a handshake
        if v:
            print(f"Pkt starts with {tls[0]}, NO HS")
        return
    
    if v:
        print(f"Handshake found for ip {ip.src}, port {tcp.sport}")

    # check that we haven't already gotten data for this client
    client = (ip.src, tcp.sport)
    with chello_lock:
        if client in chello_map:
            return
        if v:
            print(f'Adding {client}')
        chello_map[client] = (time.time(), tls)

def capture_pkts(iface="eth0", port=8443, v: bool=False):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
    s.bind((iface, 0))
    next_run = time.time() + 120
    while True:
        pkt = s.recv(0xffff)
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            parse_ip_pkt(eth.data, port, v)

        # Periodically cleanup
        if next_run < time.time():
            cleanup_map(v)
            next_run = time.time() + 120

def add_useragent(nid, norm_nid, agent):
    global psql
    conn = None
    try:
        conn = psql.conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM fingerprints WHERE id=%s", [nid])
        rows = cur.fetchall()

        # # The below implementation is removed since we implement normalization
        # if len(rows) == 0:
        #     # Unique fingerprint, need to insert
        #     db.cur.execute('''INSERT INTO fingerprints (id, record_tls_version, ch_tls_version,
        #                     cipher_suites, compression_methods, extensions, named_groups,
        #                     ec_point_fmt, sig_algs, alpn, key_share, psk_key_exchange_modes,
        #                     supported_versions, cert_compression_algs, record_size_limit)
        #                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
        #     (fid, out['tls_version'], out['ch_version'], bytea(out['cipher_suites']),
        #     bytea(out['compression_methods']), bytea(out['extensions']), bytea(out['curves']),
        #     bytea(out['pt_fmts']), bytea(out['sig_algs']), bytea(out['alpn']),\
        #     bytea(out['key_share']), bytea(out['psk_key_exchange_modes']), \
        #     bytea(out['supported_versions']), bytea(out['cert_compression_algs']),\
        #     bytea(out['record_size_limit'])))
        
        # Instead we insert to useragents only when the fingerprint is seen before to reduce overhead
        if len(rows) > 0:
            cur.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
                (int(time.time()), nid, agent))
        conn.commit()
    except Exception as e:
        print(f'add_useragent({str(nid)}, {str(norm_nid)}, {agent}) for original fp: {e}')
        if conn:
            conn.rollback()

    # No matter if the original fingerprint is seen before, we still try to insert the normalized one
    try:
        conn = psql.conn()
        cur = conn.cursor()
        # And check if the normalized fingerprint is seen before
        # db.cur.execute("SELECT * FROM fingerprints_norm_ext WHERE id=%s", [norm_fid])
        # rows = db.cur.fetchall()
        # if len(rows) > 0:
        cur.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
            (int(time.time()), norm_nid, agent))
        conn.commit()
    except Exception as e:
        print(f'add_useragent({str(nid)}, {str(norm_nid)}, {agent}) for original fp: {e}')
        if conn:
            conn.rollback()

def handle(conn):
    global chello_lock, chello_map, psql
    buf = b''
    while True:
        req = conn.recv()
        if req == '':
            break
        buf += req
        if b'\r\n\r\n' in buf:
            break


    ob = HTTPRequest(buf)
    user_agent = ''
    if 'user-agent' in ob.headers:
        user_agent = ob.headers['user-agent']

    addr, port = conn.getpeername()
    print('Req ({}:{}): {}'.format(addr, port, buf))

    out = {}
    out['addr'] = addr
    out['port'] = port
    out['agent'] = user_agent

    resp = '{"status": "error"}\n'
    client_hello = None
    with chello_lock:
        k = (socket.inet_aton(addr), port)
        if k in chello_map:
            client_hello = chello_map[k][1]

    if client_hello is not None:
        out['client_hello'] = client_hello.hex()
        fp = Fingerprint.from_tls_data(client_hello)
        if fp is not None:
           
            # fp.extensions_norm =  [0, 0, 0, 5, 0, 10, 0, 11, 0, 13, 0, 16, 0, 18, 0, 21, 0, 23, 0, 27, 0, 35, 0, 43, 0, 45, 0, 51, 10, 10, 10, 10, 68, 105, 255, 1]
            #tls_version, chello_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn, key_share, psk_key_exchange_modes, supported_versions, cert_comp_algs, record_size_limit, sni_host = res
            out['tls_version']          = fp.tls_version
            out['ch_version']           = fp.ch_version
            out['cipher_suites']        = fp.cipher_suites
            out['compression_methods']  = fp.comp_methods
            out['extensions']           = fp.extensions
            out['extensions_norm']      = fp.extensions_norm
            out['curves']               = fp.elliptic_curves
            out['pt_fmts']              = fp.ec_point_fmt
            out['sig_algs']             = fp.sig_algs
            out['alpn']                 = fp.alpn
            out['key_share']            = fp.key_share
            out['psk_key_exchange_modes'] = fp.psk_key_exchange_modes
            out['supported_versions']   = fp.supported_versions
            out['cert_compression_algs']= fp.cert_compression_algs
            out['record_size_limit']    = fp.record_size_limit
            out['sni']                  = fp.sni


            fpid = fp.get_fingerprint()
            out['nid'] = fpid # numeric id
            hid = struct.pack('!q', fpid)
            out['id'] = hid.hex() # hex id

            norm_fpid = fp.get_fingerprint_normalized()
            out['norm_nid'] = norm_fpid # numeric normalized id
            norm_hid = struct.pack('!q', norm_fpid)
            out['norm_id'] = norm_hid.hex() # hex normalized id

    resp = json.dumps(out)

    conn.write(bytes(f'HTTP/1.1 200 OK\r\nContent-type: application/json\r\nContent-Length: {len(resp)}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{resp}', 'utf-8'))
    conn.close()
    add_useragent(out['nid'], out['norm_nid'], out['agent'])

def handle_accept(ssock, addr, key, cert):
    conn = None
    try:
        conn = ssl.wrap_socket(ssock, keyfile=key, certfile=cert, server_side=True)
        print('Connection from {}:{}'.format(addr[0], addr[1]))
        handle(conn)
    except ssl.SSLError as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()

def main():
    global psql
    parser = argparse.ArgumentParser(
        prog = 'ClientHello Fingerprinter Server',
        description = 'This is a server that fingerprints TLS ClientHello messages and generates a unique ID for each unique ClientHello to be used at TLSFingerprint.io.',
        epilog = 'Copyright (c) 2023, TLSFingerprint.io')

    # parser.add_argument('-t', '--host', default='') # host to listen on
    # parser.add_argument('-p', '--port', default=8443) # port to listen on
    # parser.add_argument('-i', '--interface', default='') # interface to pcap on
    # parser.add_argument('-k', '--keyfile', default='') # keyfile for TLS
    # parser.add_argument('-c', '--certfile', default='') # certfile for TLS
    # parser.add_argument('-v', '--verbose', action='store_true')  # on/off flag
    parser.add_argument('-c', '--confiig', default='config.json') # config file
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = json.load(f)

        host = config['host']
        port = config['port']
        interface = config['interface']
        keyfile = config['key']
        certfile = config['cert']
        verbose = config['verbose']

        if interface == '':
            print('Error: No interface specified')
            sys.exit(1)

        # optional psql config
        if 'psql' in config:
            pgconf: dict = config['psql']
            psql.connect(pgconf.get('database', 'postgres'), pgconf.get('user', 'postgres'), pgconf.get('host', 'localhost'), pgconf.get('password', None), pgconf.get('port', None))

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        iface = interface

        t = threading.Thread(target=capture_pkts, args=(iface, port, verbose))
        t.setDaemon(True)
        t.start()

        while True:
            ssock, addr = sock.accept()
            t = threading.Thread(target=handle_accept, args=(ssock,addr,keyfile,certfile))
            t.setDaemon(True)
            t.start()

if __name__ == '__main__':
    main()
