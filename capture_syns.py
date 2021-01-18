#!/usr/bin/python3

import os
import subprocess as sp
import asyncio
import sys
import re


def main(args):
    print('Starting the tcpdump')
    loop = asyncio.get_event_loop()
    rc = loop.run_until_complete(tcpdump())
    loop.close()

async def tcpdump():
    proc = await asyncio.create_subprocess_exec('/usr/sbin/tcpdump', '-l',
            '-tttt', '-n', '-p', '-q', '-c', '4', '-i', 'eth0',
            'tcp[tcpflags]==tcp-syn',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE)
    tasks = [asyncio.ensure_future(process_stream(proc.stdout)),
             asyncio.ensure_future(proc.wait())]
    done, pending = await asyncio.wait(tasks)

    return proc.returncode

async def process_stream(stream):
    p = re.compile(r'(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                   r'\.\d+\s+IP\s+'
                   r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                   r'\.'
                   r'(?P<src_prt>\d+)'
                   r'\s+>\s+'
                   r'(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                   r'\.(?P<dst_prt>\d+):.*'
    )
    while not stream.at_eof():
        data = await stream.readline()
        line = data.decode('utf-8').rstrip()
        m = p.search(line)
        try:
            pkt = m.groupdict()
            print(pkt)
            # sock_lines = sp.check_output(['/bin/ss', '-ntaop'],
            #              stderr=sp.STDOUT, universal_newlines=True, timeout=2)
            # print(sock_lines)
        except Exception as e:
            pass # print(e)




if __name__ == '__main__':
    import argparse
    import sys
    import time
    parser = argparse.ArgumentParser()
    parser.add_argument('func', choices=['main'], default='main', nargs='?')
    # parser.add_argument('--option1')
    args = parser.parse_args()
    globals()[args.func](args)
