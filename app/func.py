import ipaddress
import subprocess
import requests
import xml.etree.ElementTree as eT
from requests.auth import HTTPDigestAuth
from scapy.all import Ether, ARP, srp
from app.models import Camera
from app import db

cameras = []


def camera_scan(subnet):
    _subnet = '.'.join(subnet.split('.')[0:3])
    _range = _subnet + '.1-254'
    _interface = "Ethernet"
    ip, ntbits = _range.split('-')
    all_hosts = list(ipaddress.ip_network(_subnet + '.0/24').hosts())
    ip_addresses = []
    for n in range(1, int(ntbits)+1):
        eval_ip = ".".join(ip.split('.')[:-1]) + '.' + str(n)
        ip_addresses.append(eval_ip)

    for ip in ip_addresses:
        _pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, unans = srp(_pkt, iface=_interface, timeout=0.1, verbose=False)
        for snt, recv in ans:
            if 'ac:cc:8e' in recv[Ether].src or 'b8:a4:4f' in recv[Ether].src:
                cameras.append(recv[ARP].psrc)
    need = len(cameras)
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    opn = []
    count = 0
    for i in range(len(all_hosts)):
        if count < need:
            output = subprocess.Popen(['ping', '-n', '1', '-w', '250', str(all_hosts[i])],
                                      stdout=subprocess.PIPE, startupinfo=info).communicate()[0]
            if "Destination host unreachable" in output.decode('utf-8'):
                opn.append(str(all_hosts[i]))
                count += 1
            elif "Request timed out" in output.decode('utf-8'):
                opn.append(str(all_hosts[i]))
                count += 1
            else:
                pass
        else:
            break
    i = 0
    listz = []
    for camera in cameras:
        user = 'root'
        pwd = 'ABM@ABM821'
        ip = camera
        json = {"action": "listdefinitions", "listformat": 'xmlschema',
                "group": "Network.eth0.IPAddress,Network.eth0.MACAddress"}

        s = requests.post('http://{}/axis-cgi/param.cgi'.format(ip), data=json,
                          auth=HTTPDigestAuth(user, pwd))
        make, model, mac, ip = eT.fromstring(s.text)[0].text.split(' ')[0],\
            ' '.join(eT.fromstring(s.text)[0].text.split(' ')[1:]),\
            eT.fromstring(s.text)[2][0][1].attrib['value'],\
            eT.fromstring(s.text)[2][0][0].attrib['value']
        newcam = Camera.query.filter_by(mac=mac).first()
        if newcam is None:
            newcam = Camera(make=make, model=model, mac=mac, ip=ip)
            db.session.add(newcam)
            db.session.commit()
            listz.append([make, model, mac, ip])
        else:
            continue
        i += 1
    if len(listz) == 0:
        return
    else:
        return listz


def camera_info(ip):
    info = {}
    cams = ['A', 'C', 'I', 'S']
    auth = HTTPDigestAuth('root', 'ABM@ABM821')
    c = 'MPQT'
    url = f'http://{ip}/axis-cgi/param.cgi'
    p = {'action': 'list',
         'group': 'root.Brand.Brand, \
                   root.Brand.ProdShortName, \
                   root.Network.Routing.DefaultRouter, \
                   root.Network.Hostname, \
                   root.Network.eth0.IPAddress, \
                   root.Network.eth0.SubnetMask, \
                   root.Network.eth0.MACAddress, \
                   root.Network.Resolver.NameServerList, \
                   root.Properties.Firmware.Version, \
                   root.Network.BootProto'
         }
    r = requests.get(url, params=p, auth=auth).text.replace('\n', ',').replace('=', ',').replace('root.Brand.', '')\
        .replace('root.Network.Routing.', '').replace('root.Network.eth0.', '').replace('root.Network.Resolver.', '')\
        .replace('root.Network.', '').replace('root.Properties.', '').split(',')
    d = dict(zip(r[::2], r[1::2]))

    info['fwver'] = d['Firmware.Version']
    info['make'] = d['Brand']
    info['model'] = d['ProdShortName'].replace('AXIS ', '')
    info['hostname'] = d['Hostname'].upper()
    info['dns'] = ', '.join(d['NameServerList'].split(' '))
    info['mac'] = d['MACAddress']
    info['ip'] = d['IPAddress']
    info['gateway'] = d['DefaultRouter']
    info['netmask'] = d['SubnetMask']
    if d['BootProto'] == 'dhcp':
        info['dhcp'] = 'DHCP'
    else:
        info['dhcp'] = 'Static'

    if info['model'][0] in cams:
        c = 'PACS'
    r3 = requests.get(f"https://www.axis.com/ftp/pub/axis/software/{c}/{info['model'].replace(' ','_')}/latest/ver.txt")
    if info['fwver'] < r3.text:
        info['update'] = "https://www.axis.com/ftp/pub/axis/software/" + c + "/" + info['model']\
            .replace(' ', '_') + "/latest/" + info['model'].replace(' ', '_') + ".bin"
        info['updatever'] = r3.text
    else:
        info['update'] = ''
        info['updatever'] = ''

    return info
