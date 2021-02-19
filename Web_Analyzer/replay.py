import sys
import os
import re
import gevent
import signal
import argparse
import urllib

from gevent.queue import Queue
from gevent import monkey
from gevent.pool import Pool



monkey.patch_socket()
monkey.patch_ssl()

import pycurl
import io
import sys



__version__ = '0.6'

DEFAULT_LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b"

c = pycurl.Curl()
c.setopt(c.SSL_VERIFYPEER, False)

def parse_uri(uri) :
    parsed = urllib.parse.urlparse(urllib.parse.unquote(uri))

    part = parsed.path.split('/')
    path = parsed.path
    fname = None
    ext = None
    if '.' in part[-1]:
        path = path[:-len(part[-1])]
        pt = part[-1].split('.')
        ext = pt[-1]
        fname = part[-1][:-len(pt[-1])-1]
    return path, fname, ext ,urllib.parse.parse_qs(parsed.query)

def logParse(line, result, i):
    try:
        r = line.split(' ')
        if r[3] > r[0]:  # 일반적인 경우
            result[i] = {'IP': r[0],
                         'DATE': r[3][1:], 'METHOD': r[5][1:], 'PATH': None, 'FNAME': None, 'EXT': None,
                         'VERSION': r[7][:-1], 'STATUS': r[8], 'SIZE': r[9][:-1], 'ARGS': None, 'URI': r[6]}
            result[i]['PATH'], result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                = parse_uri(r[6])
        else:
            result[i] = {'IP': r[0],
                         'DATE': r[4][1:], 'METHOD': r[6][1:], 'PATH': None, 'FNAME': None, 'EXT': None,
                         'VERSION': r[8][:-1], 'STATUS': r[9], 'SIZE': r[10][:-1], 'ARGS': None, 'URI': r[7]}
            result[i]['PATH'], result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                = parse_uri(r[7])



    except IndexError as e:  # 400에러 등 예외처리
        r = line.split(' ')
        if r[3] > r[0]:
            result[i] = {'IP': r[0],
                         'DATE': r[3][1:], 'METHOD': "-", 'PATH': None, 'FNAME': None, 'EXT': None,
                         'VERSION': "-", 'STATUS': r[6], 'SIZE': "-", 'ARGS': None, 'URI': " "}
            result[i]['PATH'], result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                = parse_uri("")
        else:
            result[i] = {'IP': r[0],
                         'DATE': r[4][1:], 'METHOD': "-", 'PATH': None, 'FNAME': None, 'EXT': None,
                         'VERSION': "-", 'STATUS': r[7], 'SIZE': "-", 'ARGS': None, 'URI': " "}
            result[i]['PATH'], result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
                = parse_uri("")

    return result

class GeventTail():
    def __init__(self, *args, **kwargs):
        self.file_name = kwargs.pop('file_name')
        try:
            self.fd = open(self.file_name, 'r' )

        except:
            self.fd = None
        self.hub = gevent.get_hub()
        self.watcher = self.hub.loop.stat(self.file_name)

    def readline(self):
        while self.fd:
            lines = self.fd.readlines()
            if lines:
                for line in lines:
                    yield line
            else:
                self.hub.wait(self.watcher)


def match_keywords(keywords, request_url):
    for k in keywords:
        if k in request_url:
            return True
    return False

result = {}
cnt = 0
def worker(args, line, line_parser):
    global result, cnt

    result = line_parser(line.encode().decode('utf-8'), result,  cnt)

    if result[cnt]['URI'] != "null":
        url = '%s%s' % (args.server.rstrip('/'), result[cnt]['URI'])
    else:
        url = '%s' % (args.server.rstrip('/'))
    match = args.match is None or match_keywords(args.match, result[cnt]['URI'])
    ignore = args.ignore is not None and match_keywords(args.ignore,  result[cnt]['URI'])

    if (match and not ignore) or args.ignore_url:
        if args.ignore_url and not (match and not ignore):
            url = args.ignore_url
        if not args.dry_run:
            buffer = io.BytesIO()
            c.setopt(c.WRITEDATA, buffer)

            c.setopt(pycurl.HTTPHEADER, [
                'User-agent: %d %s'   % (cnt,line[:-1]) ]
                     )
            cnt+=1
            # if l['request_method'] == 'GET':
            c.setopt(c.URL, url)
            c.setopt(c.HTTPGET, True)
            c.setopt(c.POST, False)
            # else:
            #     # Set POST Params as '(GET + POST) Request's GET Params'(POST Params are omitted.)
            #     c.setopt(c.POST, True)
            #     c.setopt(c.HTTPGET, False)
            #     parsed = urllib.parse.urlparse(urllib.parse.unquote(url))
            #     url = parsed.scheme+"://"+parsed.netloc+parsed.path
            #     c.setopt(c.URL, url)
            #
            #     pq = urllib.parse.parse_qs(parsed.query)
            #
            #     param = dict()
            #
            #     for i in pq:
            #         param[i] = pq[i][0]
            #
            #     c.setopt(c.POSTFIELDS, urllib.parse.urlencode(param))



            c.perform()
            res = buffer.getvalue()
            print('%s GET %s' % (url,c.getinfo(pycurl.HTTP_CODE)))




        else:
            print('[dry run] %s' % (url))
    else:
        print('[ignored] %s' % (url))


def reader(args):
    line_parser = logParse

    if args.auth is not None:
        credentials = args.auth.split(':')
        #args.auth = requests.auth.HTTPBasicAuth(credentials[0], credentials[1])
        print("Auth not implemented!")
        exit(0)

    pool = Pool(args.workers)

    gt = GeventTail(file_name=args.log_file)
    for line in gt.readline():
        pool.spawn(worker, args, line, line_parser)
    pool.join()


def main():

    gevent.signal_handler(signal.SIGTERM, gevent.kill)

    parser = argparse.ArgumentParser(
        prog='areplay',
        description='Apache Log live replay',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80)
    )

    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-a', '--auth', help='Basic authentication user:password', type=str)
    parser.add_argument('-w', '--workers', help='Workers pool size', type=int, default=50)
    parser.add_argument('-m', '--match', help='Only process matching requests', type=str)
    parser.add_argument('-i', '--ignore', help='Ignore matching requests', type=str)
    parser.add_argument('-d', '--dry-run', dest='dry_run', action='store_true', help='Only prints URLs')
    parser.add_argument('-f', '--format', help='Apache log format', type=str, default=DEFAULT_LOG_FORMAT)
    parser.add_argument('-sv', '--skip-verify', dest='verify', action='store_false', help='Skip SSL certificate verify')
    parser.add_argument('-iu', '--ignore-url', dest='ignore_url', help='URL to hit when URL from log is ignored', type=str)
    parser.add_argument('server', help='Remote Server')
    parser.add_argument('log_file', help='Apache log file path')

    args = parser.parse_args()

    if args.match is not None:
        args.match = args.match.split('|')

    if args.ignore is not None:
        args.ignore = args.ignore.split('|')

    try:
        gevent.spawn(reader, args).join()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()