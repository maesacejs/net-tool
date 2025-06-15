from flask import Flask, request, jsonify
from env_config_w import db_worker as env_config
from cidr_to_netmask import cidr_to_netmask as ctm
import requests
import re
import nmap
import subprocess
import json
import mysql.connector
import http.client
import random
import string
from datetime import datetime, timedelta
from flask_cors import CORS
import time

app = Flask(__name__)

CORS(app)

worker_access=env_config["WORKER_TOKEN"]
interface=env_config["INTERFACE"]

PUBLIC_IP = None
PUBLIC_IP_Q = None
PUBLIC_IP_ORG = None
current_device_data = {}



def get_db():
    return mysql.connector.connect(
        host=env_config["MYSQL_HOST_W"],
        user=env_config["MYSQL_USER_W"],
        password=env_config["MYSQL_PASSWORD_W"],
        database=env_config["MYSQL_DATABASE_W"]
    )

def random_code():
    digits = ''.join(random.choices(string.digits, k=2))
    letters = ''.join(random.choices(string.ascii_uppercase, k=5))
    dash = ''.join("-")
    return f"({digits}{letters}{dash})"

def pre_exisiting(name):
    return bool(name and re.match(r'^\(\d{2}[A-Z]{5}-\)', name[:10]))

def extract_hostname_suffix(name):
    match = re.match(r'^\(([^()]+)-\)', name)
    return match.group(1) if match else ''

def get_ip_data():
    try:
        result_route = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output_route = result_route.stdout 

        match = re.search(rf'default via ([\d\.]+) ([\w ]+) {re.escape(interface)} ([\w ]+) (src) ([\d\.]+)', output_route)

        if match:
            gateway_ip = match.group(1)
            own_ip = match.group(5)
        else :
            # Hard exit, network is butched
            print("Hard exit, network is butched")
            exit()

        result_a = subprocess.run(['ip', 'a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output_a = result_a.stdout

        interface_block = re.search(rf'\d+:\s+{re.escape(interface)}:.*?(?=\n\d+:|\Z)', output_a, re.DOTALL)

        block_text = interface_block.group(0)

        inet_match = re.search(rf'inet\s+{re.escape(own_ip)}+/(\d+)', block_text)
        if inet_match:
            cidr = int(inet_match.group(1))
            netmask = ctm.get(cidr)
            if not netmask:
                exit()
            return own_ip, gateway_ip, netmask

    except subprocess.CalledProcessError as e:
        print(f"Error running ip command: {e}")
        return None

def check_permissions(token):
    if token == worker_access:
        return True
    else:
        return False

@app.route('/', methods=['GET'])
def run_worker():
    start_time = time.time()
    token = request.headers.get('Authorization')
    if not check_permissions(token):
        return jsonify({"message": "Unauthorized"}), 401
    
    global PUBLIC_IP, PUBLIC_IP_Q, PUBLIC_IP_ORG, current_device_data
    own_ip, gateway, netmask = get_ip_data()

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            select d.name, dm.device_id, dm.ip_address, dm.netmask,
            dm.gateway, dm.description, dm.status, 
            dm.lastseen, dm.extra, dm.mac_address
            from nt_devices d join nt_devices_meta dm on d.id = dm.device_id
            """)
        devices = cursor.fetchall()
    except Exception as e:
        print(e)
    
    for row in devices:
        if row['name'] == 'PUBLIC_IP':
            PUBLIC_IP = row['ip_address']
            PUBLIC_DEVICE_ID = row['device_id']
        else:
            current_device_data[row['ip_address']] = row

    ip_host_mac_map = {}

    dhco_conn = http.client.HTTPConnection("10.0.0.1", 8001)
    dhco_conn.request("GET", "/dhcp-consume.txt")
    dhcp_response = dhco_conn.getresponse()
    dhcp_response_data = dhcp_response.read().decode()
    log_lines = dhcp_response_data.splitlines()

    arp_conn = http.client.HTTPConnection("10.0.0.1", 8001)
    arp_conn.request("GET", "/arp-consume.txt")
    arp_response = arp_conn.getresponse()
    arp_response_data = arp_response.read().decode()
    arp_lines = arp_response_data.splitlines()

    just_now = datetime.now()

    for line in log_lines:
        match_time = re.match(r'^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})', line)
        lastseen = None
        if match_time:
            timestamp_str = match_time.group(1)
            try:
                lastseen = datetime.strptime(f"{just_now.year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                # incase datatime gets butched.
                pass
        match_bound = re.search(r'bound to ([\d\.]+)', line)
        if match_bound:
            PUBLIC_IP_Q = match_bound.group(1)
            continue

        match_ack = re.search(r'DHCPACK on ([\d\.]+) to ([\w:]+)(?: \(([^)]+)\))?', line)
        if match_ack:
            ip, mac, hostname = match_ack.groups()
            hostname = hostname if hostname is not None else "NoName"
            print("DHCP", ip, hostname)
            ip_host_mac_map[ip] = {'mac': mac, 'hostname': hostname, 'lastseen': lastseen, 'method': "DHCP"}

    for line in arp_lines:
        if f"({gateway})" in line:
            continue
        timestamp = datetime.strptime(str(just_now), "%Y-%m-%d %H:%M:%S.%f")
        arp_lastseen = timestamp
        match_time = re.search(r'in (\d{1,4}) seconds', line)
        if match_time:
            cache = match_time.group(1)
            # ARP cachtime in gateway server is 1200 seconds net.link.ether.inet.max_age = 1200
            seconds = 1200 - int(cache)
            try:
                arp_lastseen = timestamp - timedelta(seconds)
            except ValueError:
                pass

        match_dev = re.search(r'^(.+?) \(([\d\.]+)\) at ([\w:]+)', line)
        if match_dev:
            # .home.arpa buthces hostname
            arp_hostname, arp_ip, arp_mac = match_dev.groups()
            arp_hostname = "NoName" if arp_hostname.strip() == "?" else arp_hostname.removesuffix(".home.arpa")
            if arp_ip not in ip_host_mac_map:
                    print("ARP", arp_ip, arp_hostname)
                    ip_host_mac_map[arp_ip] = {'mac': arp_mac, 'hostname': arp_hostname, 'lastseen': arp_lastseen, 'method': "ARP"}

    if PUBLIC_IP and PUBLIC_IP_Q and PUBLIC_IP != PUBLIC_IP_Q:
        result = subprocess.run(['whois', PUBLIC_IP_Q], capture_output=True, text=True)
        org_match = re.search(r'org-name:\s*(.+)', result.stdout, re.IGNORECASE)
        PUBLIC_IP_ORG = org_match.group(1).strip() if org_match else 'Unknown'

        cursor.execute("update nt_devices_meta set ip_address = %s, extra = %s where device_id = %s", 
        (PUBLIC_IP_Q, PUBLIC_IP_ORG, PUBLIC_DEVICE_ID))
        db.commit()
    
    print(ip_host_mac_map)
    
    for ip, log_data in ip_host_mac_map.items():

        uid = random_code()
        raw_hostname = log_data['hostname']
        new_hostname = f"{uid}{raw_hostname}"
        mac = log_data['mac']
        lastseen = log_data['lastseen']
        method = log_data['method']

        db_row = current_device_data.get(ip)
        
        if not db_row:
            description = ""
            found_by_mac = None
            for c_ip, c_data in current_device_data.items():
                if c_data['mac_address'] == mac:
                    found_by_mac = c_data
                    break

            if found_by_mac:
                print("Found by MAC", found_by_mac)
                db_name = found_by_mac['name']
                old_ip = found_by_mac['ip_address']
                device_id = found_by_mac['device_id']
                description = found_by_mac['description']

                if pre_exisiting(db_name):
                    if new_hostname[10:] == db_name[10:]:
                        # Already exist in the database, with same name 
                        new_name = db_name
                        status = 'Only nmap'
                    elif db_name[10:] == "NoName" and new_hostname[10:] == "NoName":
                        # NoName in db and from scan
                        new_name = db_name
                        status = 'Only nmap'
                    elif db_name[10:] == "NoName" and not new_hostname[10:] == "NoName":
                        # Scan reports actuall name but has NoName in database.
                        # Device owner may have added a hostname
                        new_name = new_hostname
                        status = "Given name"
                    elif not db_name[10:] == "NoName" and not new_hostname[10:] == "NoName":
                        # Scan found another "original name" different from existing original name 
                        new_name = f"({db_name[10:]}-){new_hostname[10:]}"
                        status = "NEED CHECK"
                        description = f"- Different original name {db_name}, {new_hostname}"
                elif db_name[:7] == "(NoName" and new_hostname[10:] == "NoName":
                    # Scan found NoName as original had NoName, now user edited.
                    new_name = db_name
                    status = "Only nmap"
                elif extract_hostname_suffix(db_name) == new_hostname[10:]:
                    new_name = db_name
                    # User edited
                    status = 'Only nmap'
                else:
                    print("NOT USER EDITED, NOT THE SAME ORIGINAL HOSTNAME")
                    new_name = new_hostname
                    status = 'NEED CHECK'
                    description = f"- Unedited and new original name {db_name}, {new_hostname}"
                try:
                    cursor.execute("update nt_devices set name = %s where id = %s", (new_name, device_id))
                    cursor.execute("""
                        update nt_devices_meta
                        set ip_address = %s, lastseen = %s, status = %s, description = %s
                        where device_id = %s
                    """, (
                        ip,
                        lastseen,
                        status,
                        f", old_ip={old_ip}, old_name={db_name}{description}",
                        device_id
                    ))
                    db.commit()
                except Exception as e:
                    print(e)
                    return jsonify({'error': str(e)}), 500
                continue

            # Inserting new device
            print("Inserting new device:", mac, ip, new_hostname)
            cursor.execute("insert into nt_devices (name) values (%s)", (new_hostname,))
            db.commit()
            new_device_id = cursor.lastrowid
            
            try:
                cursor.execute("""
                    insert into nt_devices_meta (
                        device_id, ip_address, netmask, gateway,
                        description, status, lastseen, extra, mac_address, type
                    ) values (
                        %s, %s, %s, %s,
                        %s, 'new', %s, NULL, %s, %s
                    )
                """, (
                    new_device_id, ip, netmask, gateway,
                    f' Discovered from {method}', lastseen, mac, 'Unknown'
                ))
                db.commit()
            except Exception as e:
                print(e)
                return jsonify({'error': str(e)}), 500
            continue

        device_id = db_row['device_id']
        db_mac = db_row['mac_address']
        db_name = db_row['name']
        db_lastseen = db_row['lastseen']
        db_ip = db_row['ip_address']



        # Comparing IP = IP and then the rest of the data, host and MAC
        if mac != db_mac:
            print("Hits if mac != mac")
            # MAC changed -> need to check if new MAC exists elsewhere
            print(f"CONFLICT!! In log = {ip} - {mac} - {new_hostname} and db = {db_ip} - {db_mac} - {db_name}, \n")
            conflict_device = None
            for c_ip, c_data in current_device_data.items():
                if c_data['mac_address'] == mac:
                    conflict_device = c_data
                    break
            print("conflict device = ", conflict_device,  "\n")
            
            if conflict_device:
                print(f"Log mac {mac} now with IP {ip} exist on db device {conflict_device['ip_address']} - {conflict_device['mac_address']} - {conflict_device['name']} \n")
                conflict_ip = conflict_device['ip_address']
                update_device = conflict_device['device_id']

                print("conflict_ip == ip", conflict_ip, ip)
                
                #Checking if the IP from the log exists in the db to remove it.
                second_conflict_ip = current_device_data.get(ip)
                print(second_conflict_ip)
                if second_conflict_ip:
                    for ip, log_data in ip_host_mac_map.items():
                        if not mac == second_conflict_ip.get("mac_address"):
                            print("MAC on db device does not exist in log, delete", second_conflict_ip.get("device_id"))
                            try:
                                cursor.execute("delete from nt_devices_meta where device_id = %s", second_conflict_ip.get("device_id"),)
                                cursor.execute("delete from nt_devices where id = %s", second_conflict_ip.get("device_id"),)
                                db.commit()
                            except Exception as e:
                                return jsonify({'error': str(e)}), 500
                try:
                    cursor.execute("""
                        update nt_devices_meta
                        SET ip_address = %s, lastseen = %s, status = %s, 
                        description = CONCAT(IFNULL(description, ''))
                        where device_id = %s
                    """, (
                        ip,
                        lastseen,
                        f"Updated IP",
                        f", old_ip={conflict_ip}",
                        update_device
                    ))
                    db.commit()
                except Exception as e:
                    print(e)
                    return jsonify({'error': str(e)}), 500
                
                continue

        elif extract_hostname_suffix(new_hostname) and extract_hostname_suffix(db_name):

            print(f"Always check log = {new_hostname}  and db = {db_name}")
            if pre_exisiting(db_name):
                if new_hostname[10:] == db_name[10:]:
                    print("EXISTS FROM BEFORE")    
                    new_name = db_name
                    status = 'Only nmap'
                elif db_name[10:] == "NoName" and new_hostname[10:] == "NoName":
                    print("Noname in db and from scan")
                    new_name = db_name
                    status = 'Only nmap'
                elif db_name[10:] == "NoName" and not new_hostname[10:] == "NoName":
                    print("Scan found new name, need check")
                    new_name = new_hostname
                    status = "NEED CHECK"
                elif not db_name[10:] == "NoName" and not new_hostname[10:] == "NoName":
                    print("Scan found new name, with pre exisiting")
                    new_name = f"({db_name[10:]}-){new_hostname[10:]}"
                    status = "NEED CHECK"
            elif db_name[:7] == "(NoName" and new_hostname[10:] == "NoName":
                new_name = db_name
                status = "Only nmap"
            elif extract_hostname_suffix(db_name) == new_hostname[10:]:
                new_name = db_name
                # User edited
                status = 'Only nmap'
            else:
                print("NOT USER EDITED, NOT THE SAME ORIGINAL HOSTNAME")
                new_name = new_hostname
                status = 'NEED CHECK'

            try:
                if not new_name == db_name:
                    cursor.execute("update nt_devices set name = %s where id = %s", (new_name, device_id))
                cursor.execute("""
                    update nt_devices_meta
                    set ip_address = %s, lastseen = %s, status = %s
                    where device_id = %s
                """, (
                    ip,
                    lastseen,
                    status,
                    device_id
                ))
                db.commit()
                # Ocured because of manual faffing in log-files. In case.
            except Exception as e:
                if "1062" in str(e) and "Duplicate entry" in str(e):
                        print(e, "Duplicate names")
                        continue
                else:
                    print(e)
                    return jsonify({'error': str(e)}), 500

        if lastseen != db_lastseen:
            cursor.execute("update nt_devices_meta set lastseen = %s where device_id = %s", (lastseen, device_id))
            db.commit()

    scanner = nmap.PortScanner()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            select d.name, dm.device_id, dm.ip_address, dm.extra
            from nt_devices d join nt_devices_meta dm on d.id = dm.device_id
            """)
        devices = cursor.fetchall()
    except Exception as e:
        print(e)
    
    for row in devices:
        print(row["ip_address"])
        if not row["name"] == 'PUBLIC_IP':
            ip = row["ip_address"]
            print("Hitting scanner!")

            open_ports = []
            host_name = "Unknown"
            os_name = "Unknown"

            try:
                scanner.scan(hosts=ip, arguments='-sT -Pn -T4 -O')

                if ip in scanner.all_hosts():
                    host_info = scanner[ip]
                    host_name = host_info.hostname() or "Unknown"

                    for proto in host_info.all_protocols():
                        ports = host_info[proto].keys()
                        for port in ports:
                            state = host_info[proto][port]['state']
                            if state == 'open':
                                open_ports.append(f"{port}/{proto}")

                    if 'osmatch' in host_info and host_info['osmatch']:
                        os_name = host_info['osmatch'][0]['name']

            except Exception as e:
                print(f"Error scanning {ip}: {e}")
                open_ports = ["None"]

            new_data = {
                "Host": host_name,
                "Open ports": ', '.join(open_ports) if open_ports else "None",
                "OS": os_name
            }
            result = { "Scan": [new_data] }
            extra_info = row['extra'] or ''
            old_data = None
            old_result = None

            match = re.search(r'({\s*"Scan"\s*:\s*\[.*?\]})', extra_info)
            if match:
                try:
                    old_result = json.loads(match.group(1))
                    print(old_result)
                    old_data = old_result.get("Scan", [{}])[0]
                    # set None
                except Exception:
                    old_result = None
                    old_data = None

            if old_data is None or any(
                old_data.get(k) != new_data[k] for k in new_data
            ):
                updated_extra = extra_info.strip()
                if match:
                    updated_extra = re.sub(re.escape(match.group(1)), json.dumps(result), updated_extra)
                else:
                    updated_extra += "\n" + json.dumps(result)
                updated_extra = updated_extra.strip()
                print(updated_extra)
                print("Done with", ip)
                try:
                    cursor.execute("""
                        update nt_devices_meta
                        set extra = %s
                        where ip_address = %s
                    """, (updated_extra, ip))
                    db.commit()
                except Exception as e:
                    print(e)
                    return jsonify({'error': str(e)}), 500
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            select count(*) from nt_devices;
            """)
        devices = cursor.fetchall()
    except Exception as e:
        print(e)
    print(f"Total devices in database{devices}")
    db.close()

    end_time = time.time()
    elapsed_time = end_time - start_time
    mins, secs = divmod(elapsed_time, 60)
    print(f"Handling all devices and nmap scan in {int(mins)}:{secs:.2f} ")
    return jsonify({"result":"Success"}), 200
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010)
