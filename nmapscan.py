'''
import nmap
import socket

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='sS')
    for host in nm.all_hosts():
        mac = nm[host].hostname()
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                extrainfo = nm[host][proto][port]['extrainfo']

                return 'Target : %s\nhostname : %s\nProtocol : %s\nport : %s\tstate : %s\tservice : %s\tproduct : %s\tversion : %s\textrainfo : %s' % (host, mac, proto, port, state, service, product, version, extrainfo)


if __name__ == '__main__':
    target = socket.gethostbyname('www.facebook.com')
    print(scan(target))
'''
import nmap
import socket
def scan(target):
    nmScan = nmap.PortScanner()

    nmScan.scan(target,'21-443')
    l=[]

    for host in nmScan.all_hosts():
        h=host
        state= nmScan[host].state()
        for proto in nmScan[host].all_protocols():
            protocol= proto
            lport = nmScan[host][proto].keys()
            # lport.sort()
            for port in lport:
                l.append(port)
    return   'Target : %s\nState : %s\nProtocol : %s\nOpen ports :%s '%(h,state,protocol,l)

if __name__ == '__main__':
    target = socket.gethostbyname('www.facebook.com')
    print(scan(target))
