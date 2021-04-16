import ipaddress, subprocess, requests, socket, struct, xml.etree.ElementTree as et, json
from requests.auth import HTTPDigestAuth
from types import SimpleNamespace
from scapy.all import Ether, ARP, srp
from app.models import Camera
from app import db

cameras = []

def pre2mask(prefix):
    bits = 32 - int(prefix)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << bits)))
    return netmask

def camera_scan(subnet):
    _subnet = '.'.join(subnet.split('.')[0:3])
    _range = _subnet + '.1-254'
    _interface = "Ethernet"
    ip, ntBits = _range.split('-')
    all_hosts = list(ipaddress.ip_network(_subnet + '.0/24').hosts())
    ip_addresses = []
    for n in range(1, int(ntBits)+1):
        eval_ip = ".".join( ip.split('.')[:-1] ) + '.' + str(n)
        ip_addresses.append( eval_ip )

    for ip in ip_addresses:
        _pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, unans = srp( _pkt, iface=_interface, timeout=0.1, verbose=False)
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
            output = subprocess.Popen(['ping', '-n', '1', '-w', '250', str(all_hosts[i])], stdout=subprocess.PIPE,
                                  startupinfo=info).communicate()[0]
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
        json = {"action": "listdefinitions", "listformat": 'xmlschema', "group": "Network.eth0.IPAddress,Network.eth0.MACAddress"}

        s = requests.post('http://{}/axis-cgi/param.cgi'.format(ip), data=json,
                          auth=HTTPDigestAuth(user, pwd))
        make, model, mac, ip = et.fromstring(s.text)[0].text.split(' ')[0], ' '.join(et.fromstring(s.text)[0].text.split(' ')[1:]),\
                       et.fromstring(s.text)[2][0][1].attrib['value'], et.fromstring(s.text)[2][0][0].attrib['value']
        newcam = Camera.query.filter_by(mac=mac).first()
        if newcam is None:
            newcam = Camera(make=make, model=model, mac=mac, ip=ip)
            db.session.add(newcam)
            db.session.commit()
            listz.append([make,model,mac,ip])
        else:
            continue
        i += 1
    if len(listz) == 0:
        return
    else:
        return listz

def camera_info(ip):
    info = {}
    user = 'root'
    passwd = 'ABM@ABM821'
    c = 'MPQT'
    m = 'PACS'
    url = f'http://{ip}/axis-cgi/network_settings.cgi'
    url2 = f'http://{ip}/axis-cgi/basicdeviceinfo.cgi'
    j = {"apiVersion":"1.0","method":"getNetworkInfo"}
    j2 = {'apiVersion':'1.0','method':'getAllProperties'}

    r = requests.post(url, auth=HTTPDigestAuth(user,passwd), json=j)
    r2 = requests.post(url2, auth=HTTPDigestAuth(user,passwd), json=j2)
    r = json.loads(r.text, object_hook=lambda d: SimpleNamespace(**d))
    r2 = json.loads(r2.text, object_hook=lambda d: SimpleNamespace(**d))
    info['fwver'] = r2.data.propertyList.Version
    info['make'] = r2.data.propertyList.Brand
    info['model'] = r2.data.propertyList.ProdNbr
    info['hostname'] = (r.data.system.hostname.hostname).upper()
    info['dns'] = ', '.join(r.data.system.resolver.nameServers)
    info['dhcp'] = r.data.devices[0].IPv4.configurationMode
    info['mac'] = (r.data.devices[0].macAddress).upper()
    if info['dhcp'] == 'static':
        info['ip'] = r.data.devices[0].IPv4.staticAddressConfigurations[0].address
        info['gateway'] = r.data.devices[0].IPv4.staticDefaultRouter
        info['netmask'] = pre2mask(r.data.devices[0].IPv4.staticAddressConfigurations[0].prefixLength)
    else:
        info['ip'] = r.data.devices[0].IPv4.addresses[0].address
        info['gateway'] = r.data.devices[0].IPv4.defaultRouter
        info['netmask'] = pre2mask(r.data.devices[0].IPv4.addresses[0].prefixLength)

    return info
