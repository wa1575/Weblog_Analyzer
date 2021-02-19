import sys
import os
import re
import gevent
import signal

import argparse


from gevent import monkey
from gevent.pool import Pool



monkey.patch_socket()
monkey.patch_ssl()

import pycurl
import io



__version__ = '0.6'

DEFAULT_LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b"
USER_AGENT = 'ApacheReplay/%s' % __version__


c = pycurl.Curl()
c.setopt(c.SSL_VERIFYPEER, False)




class GeventTail():
    def __init__(self, *args, **kwargs):
        self.file_name = kwargs.pop('file_name')
        try:
            self.fd = open(self.file_name, 'r' )

        except:
            self.fd = None
        self.hub = gevent.get_hub()
        self.watcher = self.hub.loop.stat(self.file_name)

    def readBlock(self):

        address_line = False
        pattern_line = False


        block = ["",""]
        while self.fd:
            lines = self.fd.readlines()
            if lines:
                for line in lines:
                    if address_line == True:
                        if line[0:11] == "User-agent:":
                            block[0] = line[:-1]
                            address_line = False
                    elif pattern_line == True:
                        if line[:8] != "Action: ":
                            block[1] += line[:-1]
                        else:
                            print(block)
                            yield block
                            block = ["", ""]
                            pattern_line = False
                    if len(line) == 15:
                        if line[10:14] == "-H--":
                            pattern_line = True
                        if line[10:14] == "-B--":
                            address_line = True



            else:
                self.hub.wait(self.watcher)


def match_keywords(keywords, request_url):
    for k in keywords:
        if k in request_url:
            return True
    return False



def worker(args, block):
    url = '%s' % (args.server.rstrip('/'))

    match = args.match is None or match_keywords(args.match, url)
    ignore = args.ignore is not None and match_keywords(args.ignore, url)

    if (match and not ignore) or args.ignore_url:
        if args.ignore_url and not (match and not ignore):
            url = args.ignore_url
        if not args.dry_run:
            buffer = io.BytesIO()
            c.setopt(c.WRITEDATA, buffer)

            url +="/?result="+str(block[1][block[1].find(" [msg "):].split(']')[0])+"]"

            c.setopt(c.URL, url)
            c.setopt(c.HTTPGET, True)
            c.setopt(c.POST, False)



            c.setopt(pycurl.HTTPHEADER, [
                block[0]]
                     )


            c.perform()
            res = buffer.getvalue()
            print('%s %s' % (url,c.getinfo(pycurl.HTTP_CODE)))


        else:
            print('[dry run] %s' % (url))
    else:
        print('[ignored] %s' % (url))


def reader(args):

    if args.auth is not None:
        credentials = args.auth.split(':')
        #args.auth = requests.auth.HTTPBasicAuth(credentials[0], credentials[1])
        print("Auth not implemented!")
        exit(0)

    pool = Pool(args.workers)

    gt = GeventTail(file_name=args.log_file)
    for block in gt.readBlock():
        pool.spawn(worker, args, block)
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