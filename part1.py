import sys
import csv
import json
import regex
import datetime
import statistics
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def execute_functions(pcap, ingest,
                       var_HTTP_sessions,
                       var_traversal,
                       var_login,
                       var_credentials,
                       var_apache,
                       var_DNS_ports,
                       var_TCP_sequences,
                       var_traceroute,
                       var_cross_site):
    http_sessions = []
    if var_HTTP_sessions.get():
        with open('HTTP_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            examiner_writer.writerow(['Webserver IP with valid HTTP session:'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                ip_src = layers.get('ip', {}).get('ip.src')
                http = layers.get('http', {})

                for key in http.keys():
                    if key.startswith('HTTP/') and 'http.response.code' in http[key]:
                        code = http[key].get('http.response.code', {})
                        if code:
                            if ip_src not in http_sessions:
                                http_sessions.append(ip_src)

            http_sessions.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
            num_columns = 6
            for ip in range(0, len(http_sessions), num_columns):
                chunk = http_sessions[ip:ip + num_columns]
                examiner_writer.writerow(chunk) 

    if var_traversal.get():
        with open('TRAVERSAL_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame_num = layers.get('frame', {}).get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                http_req_uri = layers.get('http', {}).get('http.request.full_uri')

                if http_req_uri is not None and '../..' in http_req_uri:
                    examiner_writer.writerow([f'FRAME: {frame_num}; REQUESTING IP: {ip_src}; SERVER IP: {ip_dst}'])
                    examiner_writer.writerow([f'Possible traversal in URI: {http_req_uri}'])
                    examiner_writer.writerow(['\n'])

    if var_login.get():
        with open('LOGIN_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame_num = layers.get('frame', {}).get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')

                ftp = layers.get('ftp', {})

                for key in ftp.keys():            
                    if key.startswith('USER '):
                        ftp_request_uname = ftp.get(key, {})
                        ftp_uname = ftp_request_uname.get('ftp.request.arg', {})
                        examiner_writer.writerow([f'USER: {ftp_uname}'])
                        examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])

                    if key.startswith(('331 ', '503 ')):
                        ftp_resp = ftp[key].get('ftp.response.arg', {})
                        examiner_writer.writerow([f'FTP response: {ftp_resp}'])
                        examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])

                    if key.startswith('530'):
                        ftp_resp = key
                        examiner_writer.writerow([f'FTP response: {ftp_resp}'])
                        examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])

                    if key.startswith('PASS '):
                        ftp_request_pass = ftp.get(key, {})
                        ftp_pass = ftp_request_pass.get('ftp.request.arg', {})
                        examiner_writer.writerow([f'PASSWORD: {ftp_pass}'])
                        examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])

    telnet_scrape = []
    if var_credentials.get():
        with open('TELNET_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                telnet = layers.get('telnet', {})

                for key in telnet.keys():
                    if key.endswith('.data'):
                        telnet_data = telnet.get(key, {})
                        telnet_scrape.append(telnet_data)
            examiner_writer.writerow([f'Clear text credentials found here:'])
            examiner_writer.writerow([f'{telnet_scrape}'])
            examiner_writer.writerow(['\n'])

            clean = lambda x: ''.join([i.strip() for i in [regex.sub(r'[^\x20-\x7E]', '', item) for item in x]])
            credentials = clean(telnet_scrape)
            examiner_writer.writerow([f'{credentials}'])

    apache_ver = {}
    if var_apache.get():
        with open('APACHE_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                http_srv = layers.get('http', {}).get('http.server', {})

                if 'Apache/' in http_srv:
                    version = regex.findall(r'(?:Apache/?)(\d.\d{1,3}(?:.\d{1,3}))', http_srv)
                    for v in version:
                        if v not in apache_ver.values():
                            apache_ver[ip_src] = [v]      

            sorted_ver = dict(sorted(apache_ver.items(), key = lambda item: tuple(map(int, item[1][0].split('.')))))

            for ip, ver in sorted_ver.items():
                examiner_writer.writerow([f'Apache server IP: {ip}', f'VERSION: {ver}'])        

    query_clients = {}
    if var_DNS_ports.get():
        with open('DNS_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                dns_resp_flag = layers.get('dns', {}).get('dns.flags_tree', {}).get('dns.flags.response')
                udp_src = layers.get('udp', {}).get('udp.srcport')

                if dns_resp_flag == '0':
                    if ip_src in query_clients:
                        query_clients[ip_src]['ports'].add(udp_src)
                        query_clients[ip_src]['count'] += 1
                    else:
                        query_clients[ip_src] = {'ports': {udp_src}, 'count': 1}

            for ip_src, val in query_clients.items():
                if len(val['ports']) == 1 and val['count'] > 1:
                    examiner_writer.writerow([f'CLIENT IP: {ip_src}; UDP PORT: {list(val["ports"])[0]}; COUNT: {val["count"]}'])

    client_seq = {}
    if var_TCP_sequences.get():
        with open('CLIENT_TCP_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                tcp_seq = layers.get('tcp', {}).get('tcp.seq_raw', None)

                if tcp_seq is not None:
                    if ip_src in client_seq:
                        client_seq[ip_src].append(tcp_seq)
                    else:
                        client_seq[ip_src] = [tcp_seq]

            tcp_deviation = {}
            for ip_src, tcp_seq in client_seq.items():
                if len(tcp_seq) >= 5:
                    int_tcp_seq  = [int(x) for x in tcp_seq]
                    std_dev = statistics.stdev(int_tcp_seq)
                    tcp_deviation[ip_src] = [std_dev]

            sort_deviation = dict(sorted(tcp_deviation.items(), key=lambda item: item[1][0], reverse=True))
            top_two = list(sort_deviation.keys())[:2]
            for client in top_two:
                examiner_writer.writerow([f'CLIENT IP: {client}', f'STANDARD DEVIATION: {sort_deviation[client][0]}'])

    traceroute_src = {}
    if var_traceroute.get():
        with open('TRACEROUTE_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame_num = layers.get('frame', {}).get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                ip_ttl = layers.get('ip', {}).get('ip.ttl')
                udp_src = layers.get('udp', {}).get('udp.srcport')

                if ip_ttl is not None and int(ip_ttl) < 64:  
                    if udp_src is not None and int(udp_src) >= 33434:  
                        if ip_src in traceroute_src:
                            traceroute_src[ip_src].append((ip_dst, frame_num))

                        else:
                            traceroute_src[ip_src] = [(ip_dst, frame_num)]

            for src, val_list in traceroute_src.items():
                examiner_writer.writerow([f'Possible source of traceroute: {src}, with '+str(len(val_list))+' occurrences'])
                for dest, frame in val_list:
                    examiner_writer.writerow([f'Source: {src}, with destination: {dest}, in frame: {frame}'])
            examiner_writer.writerow(['\n'])


    xss_RedFlags = {'<' : 1,
                    '>' : 1,
                    'script' : 1,
                    '%3C' : 2,
                    '%3E' : 2,
                    '.cookie' : 5,
                    'test' : 10,
                    '%22' : 10,
                    'alert(' : 10,
                    '%253C' : 10,
                    '%253E' : 10,
                    '&#60;': 10,
                    '&#62;' : 10,
                    '(String.fromCharCode(' : 20,
                    'eval(atob(' : 20,
                    '.nasl' : 30
                    }
    if var_cross_site.get():
        with open('XSS_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            matches = []
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame_num = layers.get('frame', {}).get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                http_req_uri = layers.get('http', {}).get('http.request.full_uri')

                score = sum(weight * http_req_uri.count(pattern) for pattern, weight in xss_RedFlags.items()
                            if http_req_uri is not None and pattern in http_req_uri)

                if score > 0:
                    matches.append((score, frame_num, ip_src, ip_dst, http_req_uri))

            for score, frame_num, ip_src, ip_dst, http_req_uri in sorted(matches, reverse=True):
                examiner_writer.writerow([f'XSS PATERN FOUND IN FRAME NUMBER: {frame_num}; REQUESTING IP: {ip_src}; SERVER IP: {ip_dst}; SCORE: {score}'])
                examiner_writer.writerow([f'{http_req_uri}'])

def main():
    root = tk.Tk()
    root.withdraw()

    filename = filedialog.askopenfilename(title="Select a file", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])

    if filename:

        with open(filename, 'r', encoding='utf-8') as pcap:
            ingest = json.load(pcap)
            
            root = tk.Tk()
            tk.Label(root, text = 'Make one or more selections:').pack(pady=10)

            var_HTTP_sessions =     tk.IntVar(value=0, master=root)
            var_traversal =         tk.IntVar(value=0, master=root)
            var_login =             tk.IntVar(value=0, master=root)
            var_credentials =       tk.IntVar(value=0, master=root)
            var_apache =            tk.IntVar(value=0, master=root)
            var_DNS_ports =         tk.IntVar(value=0, master=root)
            var_TCP_sequences =     tk.IntVar(value=0, master=root)
            var_traceroute =        tk.IntVar(value=0, master=root)
            var_cross_site =        tk.IntVar(value=0, master=root)

            ttk.Checkbutton(root, text = 'Examine HTTP sessions',           variable = var_HTTP_sessions).pack(anchor='w')            
            ttk.Checkbutton(root, text = 'Possible directory traversals',   variable = var_traversal).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Failed login attempts',           variable = var_login).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Clear text credentials',          variable = var_credentials).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Apache webserver versions',       variable = var_apache).pack(anchor='w')
            ttk.Checkbutton(root, text = 'DNS source port randomization',   variable = var_DNS_ports).pack(anchor='w')
            ttk.Checkbutton(root, text = 'TCP ISN deviation',               variable = var_TCP_sequences).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Traceroute evidence',             variable = var_traceroute).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Possible XSS events',             variable = var_cross_site).pack(anchor='w')
            
            ttk.Button(root, text='Execute Selected Functions', command = lambda: [execute_functions(pcap, ingest,
                                                                                                    var_HTTP_sessions,
                                                                                                    var_traversal,
                                                                                                    var_login,
                                                                                                    var_credentials,
                                                                                                    var_apache,
                                                                                                    var_DNS_ports,
                                                                                                    var_TCP_sequences,
                                                                                                    var_traceroute,
                                                                                                    var_cross_site), re_execute(root)]).pack(pady=10)            
            root.mainloop()
    else:
        print("No file selected")
        sys.exit()

def re_execute(root):
    root.destroy()

    run_again = messagebox.askyesno(title='', message='Would you like to run another function?')
    if run_again:
        main()
    if not run_again:
        sys.exit()

if __name__ == "__main__":
    main()
