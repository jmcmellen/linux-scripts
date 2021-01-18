#!/usr/bin/python3

# This doesn't seem to be working so far, getting IO errors trying to write to
# the kprobe_events file. Oh, I had to fix the name of the function.
# Here's some more notes.
# Convert addr to dotted
# python3 -c $'import socket\nprint(socket.inet_ntoa(int(1392120748).to_bytes(4, "little")))'
# Convert dotted to addr
# python3 -c $'import socket\nprint(int().from_bytes(socket.inet_aton("127.0.0.1"), "little")))'
# Convert port to host format
# python3 -c $'import socket\nprint(socket.ntohs(13568))'
# These are the 'type' field
#   /* Supported address families. */
#   #define AF_UNSPEC	0
#   #define AF_UNIX		1	/* Unix domain sockets 		*/
#   #define AF_INET		2	/* Internet IP Protocol 	*/
#   #define AF_AX25		3	/* Amateur Radio AX.25 		*/
#   #define AF_IPX		4	/* Novell IPX 			*/
#   #define AF_APPLETALK	5	/* Appletalk DDP 		*/
#   #define	AF_NETROM	6	/* Amateur radio NetROM 	*/
#   #define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#   #define AF_AAL5		8	/* Reserved for Werner's ATM 	*/
#   #define AF_X25		9	/* Reserved for X.25 project 	*/
#   #define AF_INET6	10	/* IP version 6			*/
#   #define AF_MAX		12	/* For now.. */

import asyncio
import re
import time
import os
import sys
import socket


# Create a custom kprobe, call it "plumber_sys_connect"
CR_CONNECT = "plumber_sys_connect" # Global

# Disable all tracers
def disableTrace():
    open("events/kprobes/%s/enable" % CR_CONNECT, 'w').write('0')
    try:
        open("kprobe_events", 'w').write("-:" + CR_CONNECT)
    except:
        print("Couldn't disable selectively, removing all kprobes")
        open("kprobe_events", 'w').write('')
    open("trace", 'w').write('')
    print("Cleaning up")

# Enable the tracers
def enableTrace():
    with open("kprobe_events", "w") as f:
        f.write("p:%s __sys_connect" % CR_CONNECT)

        f.write(" type=+0(%si):u16 port=+2(%si):u16 addr=+4(%si):u32")

    open("events/kprobes/%s/filter" % CR_CONNECT, 'w').write('type != 1')
    open("events/kprobes/%s/enable" % CR_CONNECT, 'w').write('1')

async def process_stream(stream, parserRE):
    p = re.compile(parserRE)
    af = {'2':'IPv4', '10':'IPv6'}
    for line in stream:
        m = p.search(line)
        try:
            pkt = dict(m.groupdict())
            # print(line, end='')
            pkt['addr'] = socket.inet_ntoa(int(pkt['addr']).to_bytes(4, "little"))
            pkt['port'] = socket.ntohs(int(pkt['port']))
            pkt['type'] = af[pkt['type']]
            print(pkt)
        except Exception as e:
            print(e)
        await asyncio.sleep(0)

async def main(args):
    # Bail out if not root/sudo
    if not os.geteuid() == 0:
        sys.exit("Error: You need to be root to run this")

    # Change to the tracer dir
    os.chdir("/sys/kernel/debug/tracing")

    print(os.getcwd())
    parserRE = r'^\s*(?P<process>\S+)\s+(\S+)\s+(\S+)\s+(?P<time>\S+):\s(?P<probe>\S+):\s+(?P<func>\S+)\s+type=(?P<type>\S+)\s+port=(?P<port>\S+)\s+addr=(?P<addr>\S+)\s*.*$'

    # Disable trace in case we didn't exit clean last time
    try:
        disableTrace()
    except IOError:
        pass

    try:
        enableTrace()
        t = open("trace_pipe", "r", encoding="utf-8", buffering=1)
        tasks = [asyncio.ensure_future(process_stream(t, parserRE)),
                 asyncio.ensure_future(asyncio.sleep(30))]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for thing in pending:
            thing.cancel()
            print("Time's up, canceling")
        await asyncio.wait(pending)
        t.close()
        raise Exception
    except:
        disableTrace()




if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('func', choices=['main'], default='main', nargs='?')
    parser.add_argument('--option1')
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(globals()[args.func](args))
    except:
        disableTrace()
