"""ISOTP HTTP GATEWAY.

Usage:
  gateway.py start [-c=<url>, --txid=<id>]
  gateway.py (-h | --help)
  gateway.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --txid=<id>   CAN arbitration ID for transmission [default: 0x90].
  -c=<url>      URL of controller [default: http://localhost:8888].

"""
from docopt import docopt
import threading
import time
import isotp
import requests


class ThreadedSocket(object):

    def __init__(self, url, rxid, txid):
        self.url = url
        self.rxid = rxid
        self.txid = txid
        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True
        self.thread.start()
    
    def socket(self):
        s = isotp.socket()
        s.set_fc_opts(stmin=5, bs=10)
        s.bind("vcan0", isotp.Address(rxid=self.rxid, txid=self.txid))
        return s

    def run(self):
        s = self.socket()
        while True:
            try:
                data = s.recv()
            except OSError:
                # I'm not sure why we have to do this, but if there is not recv() on the other end of the socket
                # the next recv will throw an OSError. Looks like this is something known.
                # https://www.spinics.net/lists/linux-can/msg07419.html
                print('exception was thrown from the socket. have recv ready prior to send.')
                s.close()
                s = self.socket()
                continue
            if data:
                sid = "{:x}".format(int(data[0]))
                o = {'sid': sid, 'data': data[1:].hex()}
                r = requests.post('{0}/uds/{1}'.format(self.url, int_to_hex_formatted_string(self.rxid)), json=o)
                x = r.json()
                s.send(bytes.fromhex(x['sid']) + bytes.fromhex(x['data']))
            else:
                time.sleep(0.2)


def int_to_hex_formatted_string(i):
    return '{0:#0{1}x}'.format(i, 4)


def get_instances(url):
    return requests.get('{0}/instances'.format(url)).json()


def run(args):
    instances = get_instances(args['-c'])
    threads = []
    for instance in instances:
        rxid = int((instance['id'][2:]), 16)
        txid = int(args['--txid'], 16)
        if rxid > 0xFF:
            continue
        t = ThreadedSocket(url=args['-c'], rxid=rxid, txid=txid)
        print('starting thread for id: {0} level: {1} rxid: {2} txid: {3}'.format(instance['id'], instance['name'],
                                                                                  int_to_hex_formatted_string(rxid),
                                                                                  int_to_hex_formatted_string(txid)))
        threads.append(t)
    for t in threads:
        t.thread.join()


if __name__ == '__main__':
    arguments = docopt(__doc__, version='1.0')
    run(arguments)
