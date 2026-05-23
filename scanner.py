import sys
import os
import socket
import urllib.request
import json
import ipaddress
import threading
import queue
import math
import random
import bisect
import time
from datetime import datetime
import string
import ssl
import subprocess

try:
    import dns.resolver
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
import warnings
from tqdm import TqdmExperimentalWarning
warnings.filterwarnings("ignore", category=TqdmExperimentalWarning)
from tqdm.rich import tqdm as rtqdm

console = Console()

def display_banner():
    banner = r"""[bold cyan]

  _____ _____     _____                                 
 |_   _|  __ \   / ____|                                
   | | | |__) | | (___   ___ __ _ _ __  _ __   ___ _ __ 
   | | |  ___/   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  _| |_| |       ____) | (_| (_| | | | | | | |  __/ |   
 |_____|_|      |_____/ \___\__,_|_|_|_|_|_|_|\___|_|   
  ____                           ____ 
 |  _ \                         |  _ \___  / \ | |      
 | |_) |_   _   _ __ ___  _ __  | |_) | / /|  \| |      
 |  _ <| | | | | '_ ` _ \| '__| |  _ < / / | . ` |      
 | |_) | |_| | | | | | | | |    | |_) / /__| |\  |      
 |____/ \__, | |_| |_| |_|_|    |____/_____|_| \_|      
         __/ |                                          
        |___/                                           

    [magenta]Multi-threaded TUI Scanner[/magenta]
    [dim]with Default Cloudflare Configurations[/dim]
[/bold cyan]"""
    console.print(Panel.fit(banner, border_style="bold blue"))

class IPTargets:
    def __init__(self, networks):
        self.ranges = []
        self.cumulative = []
        self.total = 0
        
        for net in networks:
            try:
                if '-' in net:
                    start_str, end_str = net.split('-', 1)
                    start_ip = int(ipaddress.IPv4Address(start_str.strip()))
                    end_ip = int(ipaddress.IPv4Address(end_str.strip()))
                    if start_ip > end_ip:
                        start_ip, end_ip = end_ip, start_ip
                    size = end_ip - start_ip + 1
                    self.ranges.append((start_ip, end_ip))
                    self.total += size
                    self.cumulative.append(self.total)
                elif '/' in net:
                    network = ipaddress.IPv4Network(net.strip(), strict=False)
                    start_ip = int(network.network_address)
                    end_ip = int(network.broadcast_address)
                    size = end_ip - start_ip + 1
                    self.ranges.append((start_ip, end_ip))
                    self.total += size
                    self.cumulative.append(self.total)
                else:
                    ip_obj = int(ipaddress.IPv4Address(net.strip()))
                    self.ranges.append((ip_obj, ip_obj))
                    self.total += 1
                    self.cumulative.append(self.total)
            except ValueError as e:
                console.print(f"[bold red]Invalid IP format skipped: {net} ({e})[/bold red]")
                
    def get_ip(self, index):
        if index < 0 or index >= self.total:
            raise IndexError("IP index out of range")
        i = bisect.bisect_right(self.cumulative, index)
        if i == 0:
            offset = index
        else:
            offset = index - self.cumulative[i-1]
        
        start_ip, _ = self.ranges[i]
        return start_ip + offset

def get_prime_factors(n):
    factors = set()
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n //= 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            factors.add(d)
            while n % d == 0:
                n //= d
        d += 2
    if n > 2:
        factors.add(n)
    return factors

def get_lcg_params(m):
    factors = get_prime_factors(m)
    a_minus_1 = 1
    for f in factors:
        a_minus_1 *= f
    if (m % 4 == 0) and (a_minus_1 % 4 != 0):
        a_minus_1 *= 2
        
    max_k = max(1, m // a_minus_1)
    k = random.randint(1, max_k)
    a = k * a_minus_1 + 1
    if a >= m:
        a = a_minus_1 + 1
        if a >= m:
             a = 1
    
    c = random.randint(1, m - 1)
    while math.gcd(c, m) != 1:
        c = (c + 1) % m
        if c == 0:
            c = 1
            break
            
    return a, c

def random_ip_indices_lcg(total_ips):
    if total_ips == 0:
        return
    if total_ips == 1:
        yield 0
        return
    if total_ips <= 100000:
        l = list(range(total_ips))
        random.shuffle(l)
        yield from l
        return

    a, c = get_lcg_params(total_ips)
    x = random.randint(0, total_ips - 1)
    for _ in range(total_ips):
        yield x
        x = (a * x + c) % total_ips

def sequential_ip_indices(total_ips):
    for i in range(total_ips):
        yield i

def ask_with_folder_choices(prompt_title, folder_paths, default=""):
    if isinstance(folder_paths, str):
        folder_paths = [folder_paths]
        
    file_entries = []
    for folder in folder_paths:
        if os.path.exists(folder):
            for f in os.listdir(folder):
                if f.endswith(".txt"):
                    file_entries.append((f[:-4], folder))
                    
    file_entries.sort(key=lambda x: (x[0].lower(), x[1]))
    
    if file_entries:
        console.print(f"\n[cyan]Available options:[/cyan]")
        for idx, (name, folder) in enumerate(file_entries, 1):
            console.print(f"  [yellow]{idx}[/yellow]. {name} [dim]({folder})[/dim]")
        console.print("[dim]Type number(s) separated by commas, or enter a custom value.[/dim]")
        
    choice = Prompt.ask(f"[bold green]{prompt_title}[/bold green]", default=default)
    if not choice.strip():
        return choice
        
    selected_items = []
    for part in choice.split(','):
        part = part.strip()
        if part.isdigit() and file_entries:
            idx = int(part)
            if 1 <= idx <= len(file_entries):
                selected_items.append(file_entries[idx-1][0])
            else:
                selected_items.append(part)
        else:
            selected_items.append(part)
            
    return ", ".join(selected_items)

def parse_ip_input(input_str):
    if not input_str.strip():
        input_str = 'cloudflare'
        
    networks = []
    items = [i.strip() for i in input_str.split(',') if i.strip()]
    for item in items:
        if os.path.isfile(item):
            try:
                with open(item, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            networks.append(line)
            except Exception as e:
                console.print(f"[bold red]Failed to read file {item}: {e}[/bold red]")
        elif os.path.isfile(os.path.join("ip_ranges", f"{item}.txt")):
            filepath = os.path.join("ip_ranges", f"{item}.txt")
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            networks.append(line)
            except Exception as e:
                console.print(f"[bold red]Failed to read file {filepath}: {e}[/bold red]")
        elif os.path.isfile(os.path.join("custom_ranges", f"{item}.txt")):
            filepath = os.path.join("custom_ranges", f"{item}.txt")
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            networks.append(line)
            except Exception as e:
                console.print(f"[bold red]Failed to read file {filepath}: {e}[/bold red]")
        else:
            networks.append(item)
            
    return networks

def parse_ports(input_str):
    if not input_str.strip():
        input_str = 'cloudflare'
        
    ports = []
    items = [i.strip() for i in input_str.split(',') if i.strip()]
    for p in items:
        filepath = os.path.join("port_ranges", f"{p}.txt")
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            for part in line.split(','):
                                part = part.strip()
                                if '-' in part:
                                    try:
                                        start, end = part.split('-', 1)
                                        ports.extend(range(int(start), int(end) + 1))
                                    except:
                                        pass
                                elif part:
                                    try:
                                        ports.append(int(part))
                                    except:
                                        pass
            except Exception as e:
                console.print(f"[bold red]Failed to read file {filepath}: {e}[/bold red]")
        elif '-' in p:
            try:
                start, end = p.split('-', 1)
                ports.extend(range(int(start), int(end) + 1))
            except:
                console.print(f"[bold red]Invalid port range skipped: {p}[/bold red]")
        else:
            try:
                ports.append(int(p))
            except:
                console.print(f"[bold red]Invalid port skipped: {p}[/bold red]")
    return sorted(list(set(ports)))

def parse_sni_input(input_str):
    snis = []
    items = [i.strip() for i in input_str.split(',') if i.strip()]
    for item in items:
        if os.path.isfile(item):
            try:
                with open(item, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            snis.append(line)
            except Exception as e:
                console.print(f"[bold red]Failed to read file {item}: {e}[/bold red]")
        elif os.path.isfile(os.path.join("sni", f"{item}.txt")):
            filepath = os.path.join("sni", f"{item}.txt")
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            snis.append(line)
            except Exception as e:
                console.print(f"[bold red]Failed to read file {filepath}: {e}[/bold red]")
        else:
            snis.append(item)
    return list(dict.fromkeys(snis))

def load_ip_ranges_map():
    range_map = {}
    if not os.path.exists("ip_ranges"):
        return range_map
    for filename in os.listdir("ip_ranges"):
        if filename.endswith(".txt"):
            name = filename[:-4]
            filepath = os.path.join("ip_ranges", filename)
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '-' in line:
                                try:
                                    s, e = line.split('-', 1)
                                    start_ip = int(ipaddress.IPv4Address(s.strip()))
                                    end_ip = int(ipaddress.IPv4Address(e.strip()))
                                    if start_ip > end_ip:
                                        start_ip, end_ip = end_ip, start_ip
                                    if name not in range_map: range_map[name] = []
                                    range_map[name].append(("range", start_ip, end_ip))
                                except: pass
                            elif '/' in line:
                                try:
                                    network = ipaddress.IPv4Network(line, strict=False)
                                    start_ip = int(network.network_address)
                                    end_ip = int(network.broadcast_address)
                                    if name not in range_map: range_map[name] = []
                                    range_map[name].append(("range", start_ip, end_ip))
                                except: pass
                            else:
                                try:
                                    ip_obj = int(ipaddress.IPv4Address(line))
                                    if name not in range_map: range_map[name] = []
                                    range_map[name].append(("single", ip_obj))
                                except: pass
            except:
                pass
    return range_map

def get_ip_range_name(ip_str, range_map):
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        for name, blocks in range_map.items():
            for block in blocks:
                if block[0] == "range" and block[1] <= ip_int <= block[2]:
                    return name
                elif block[0] == "single" and block[1] == ip_int:
                    return name
    except:
        pass
    return "Unknown"

def worker(task_queue, timeout, results, lock, pbar, cancel_event, scan_mode="tcp"):
    while not cancel_event.is_set():
        try:
            target = task_queue.get(timeout=0.5)
        except queue.Empty:
            continue
            
        if target is None:
            task_queue.task_done()
            break
            
        ip, port = target
        try:
            start_t = time.time()
            if scan_mode == "handshake":
                # Mimic curl -kI ip:port — single connection, any response = success
                got_response = False
                
                # --- Attempt 1: HTTPS (TLS + HTTP HEAD) on same socket ---
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((ip, port))
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls_sock = ctx.wrap_socket(sock, server_hostname=ip)
                    sock = None  # tls_sock now owns the underlying socket
                    tls_sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
                    resp = tls_sock.recv(512)
                    if resp and len(resp) > 0:
                        got_response = True
                    tls_sock.close()
                except Exception:
                    try:
                        if sock: sock.close()
                    except: pass
                
                # --- Attempt 2: Plain HTTP HEAD (only if TLS failed) ---
                if not got_response:
                    sock = None
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        sock.connect((ip, port))
                        sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
                        resp = sock.recv(512)
                        if resp and len(resp) > 0:
                            got_response = True
                        sock.close()
                    except Exception:
                        try:
                            if sock: sock.close()
                        except: pass
                
                if got_response:
                    delay = int((time.time() - start_t) * 1000)
                    with lock:
                        results.append((ip, port, delay))
                        count = len(results)
                        recent = ", ".join([f"{r[0]}:{r[1]}({r[2]}ms)" for r in results[-3:]])
                        pbar.set_postfix_str(f"✔ {count} | {recent}", refresh=False)
            else:
                # TCP-only: connection success is enough
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    delay = int((time.time() - start_t) * 1000)
                    with lock:
                        results.append((ip, port, delay))
                        count = len(results)
                        recent = ", ".join([f"{r[0]}:{r[1]}({r[2]}ms)" for r in results[-3:]])
                        pbar.set_postfix_str(f"✔ {count} | {recent}", refresh=False)
                sock.close()
        except Exception:
            pass
            
        if not cancel_event.is_set():
            pbar.update(1)
        task_queue.task_done()

def icmp_worker(task_queue, timeout, results, lock, pbar, cancel_event):
    while not cancel_event.is_set():
        try:
            target = task_queue.get(timeout=0.5)
        except queue.Empty:
            continue
            
        if target is None:
            task_queue.task_done()
            break
            
        ip = target
        try:
            timeout_int = max(1, int(timeout))
            start_t = time.time()
            # Use ping -c1 with timeout; works without root unlike raw ICMP sockets
            if sys.platform == "darwin":
                cmd = ["ping", "-c", "1", "-t", str(timeout_int), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout_int), ip]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_int + 2)
            if result.returncode == 0:
                delay = int((time.time() - start_t) * 1000)
                with lock:
                    results.append((ip, 0, delay))
                    count = len(results)
                    recent = ", ".join([f"{r[0]}({r[2]}ms)" for r in results[-3:]])
                    pbar.set_postfix_str(f"✔ {count} | {recent}", refresh=False)
        except (subprocess.TimeoutExpired, Exception):
            pass
            
        if not cancel_event.is_set():
            pbar.update(1)
        task_queue.task_done()

def scanner_tool():
    
    # 1. Ask for Target Ranges
    console.print()
    console.print("[cyan]➜[/cyan] [bold]Enter IP targets[/bold] (comma separated IPs, CIDRs, ranges, or .txt files).")
    console.print("  [dim]Leave empty or type 'cloudflare' for Cloudflare IP ranges.[/dim]")
    ip_input = ask_with_folder_choices("IP Ranges", ["ip_ranges", "custom_ranges"], default="cloudflare")
    networks = parse_ip_input(ip_input)
    
    ip_targets = IPTargets(networks)
    if ip_targets.total == 0:
        console.print("[bold red]No valid IP address targets provided. Going back.[/bold red]")
        return
        
    console.print(f"[green]✔[/green] Loaded [bold white]{ip_targets.total:,}[/bold white] total IPs to scan.")

    # 2. Ask for Scan Mode (before ports, since ICMP doesn't need ports)
    console.print("[cyan]➜[/cyan] [bold]Scan Mode[/bold]")
    console.print("  [yellow]1[/yellow]. TCP Connect [dim](fast, checks if port is open)[/dim]")
    console.print("  [yellow]2[/yellow]. TLS Handshake [dim](slower, verifies TLS/SSL + data flow)[/dim]")
    console.print("  [yellow]3[/yellow]. ICMP Ping [dim](checks if host is alive, no port needed)[/dim]")
    scan_mode_choice = Prompt.ask("Select scan mode", choices=["1", "2", "3"], default="1")
    if scan_mode_choice == "1":
        scan_mode = "tcp"
    elif scan_mode_choice == "2":
        scan_mode = "handshake"
    else:
        scan_mode = "icmp"
    
    mode_labels = {"tcp": "TCP Connect", "handshake": "TLS Handshake", "icmp": "ICMP Ping"}
    console.print(f"[green]✔[/green] Scan mode: [bold white]{mode_labels[scan_mode]}[/bold white]")
    
    # 3. Ask for Target Ports (skip for ICMP)
    ports = []
    if scan_mode != "icmp":
        console.print("[cyan]➜[/cyan] [bold]Enter target ports[/bold] (comma separated or ranges like 80-90).")
        console.print("  [dim]Leave empty or type 'cloudflare' for Cloudflare standard ports.[/dim]")
        port_input = ask_with_folder_choices("Ports", "port_ranges", default="cloudflare")
        ports = parse_ports(port_input)
        
        if not ports:
            console.print("[bold red]No valid ports provided. Going back.[/bold red]")
            return
            
        console.print(f"[green]✔[/green] Loaded [bold white]{len(ports)}[/bold white] ports to scan: {ports}")
    
    # 4. Ask for Threads and Timeout
    console.print("[cyan]➜[/cyan] [bold]Scan Configuration[/bold]")
    default_threads = 100 if scan_mode == "icmp" else 500
    num_threads = IntPrompt.ask("Number of threads", default=default_threads)
    timeout = float(Prompt.ask("Timeout (seconds)", default="2.0" if scan_mode == "icmp" else "1.0"))
    is_random = Confirm.ask("Randomize IP search order? (Helps find open IPs sooner)", default=True)
    
    max_ips = 0
    if is_random and ip_targets.total > 10:
        limit_input = Prompt.ask("Max IPs to scan (leave empty for no limit)", default="")
        limit_clean = limit_input.strip().replace('_', '').replace(',', '')
        if limit_clean.isdigit():
            max_ips = int(limit_clean)

    console.print()

    # Pre-checks before starting
    search_ips_count = ip_targets.total
    if 0 < max_ips < ip_targets.total:
        search_ips_count = max_ips
    
    if scan_mode == "icmp":
        total_targets = search_ips_count  # 1 task per IP, no ports
    else:
        total_targets = search_ips_count * len(ports)
    
    table = Table(title="Scan Configuration", title_style="bold magenta", border_style="cyan")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    
    table.add_row("Total Available IPs", f"{ip_targets.total:,}")
    if 0 < max_ips < ip_targets.total:
        table.add_row("Scanning IPs Limit", f"{max_ips:,}")
    if scan_mode != "icmp":
        table.add_row("Target Ports", f"{len(ports)}")
    table.add_row("Total Tasks", f"{total_targets:,}")
    table.add_row("Threads", str(num_threads))
    table.add_row("Timeout", f"{timeout}s")
    table.add_row("Scan Mode", mode_labels[scan_mode])
    table.add_row("Search Order", "Randomized (LCG)" if is_random else "Sequential")
    
    console.print(table)
    console.print()
    
    if total_targets > 1_000_000 and not is_random:
        console.print("[bold yellow]⚠ Warning: You are initiating a sequential scan over 1M IPs![/bold yellow]")
        if not Confirm.ask("Do you want to proceed?"):
            console.print("[bold red]Scan aborted by user.[/bold red]")
            return

    task_queue = queue.Queue(maxsize=1_000_000)
    results = []
    lock = threading.Lock()
    threads = []
    cancel_event = threading.Event()
    
    console.print("[bold blue]Starting Scanner... (Press Ctrl+C to stop early)[/bold blue]")
    start_time = datetime.now()
    
    try:
        unit_label = "ip" if scan_mode == "icmp" else "port"
        with rtqdm(total=total_targets, desc="[magenta]Scanning[/magenta]", unit=unit_label) as pbar:
            # Start worker threads
            if scan_mode == "icmp":
                for _ in range(num_threads):
                    t = threading.Thread(target=icmp_worker, args=(task_queue, timeout, results, lock, pbar, cancel_event), daemon=True)
                    t.start()
                    threads.append(t)
            else:
                for _ in range(num_threads):
                    t = threading.Thread(target=worker, args=(task_queue, timeout, results, lock, pbar, cancel_event, scan_mode), daemon=True)
                    t.start()
                    threads.append(t)
                
            if is_random:
                ip_gen = random_ip_indices_lcg(ip_targets.total)
            else:
                ip_gen = sequential_ip_indices(ip_targets.total)

            scanned_ips = 0
            for ip_index in ip_gen:
                if cancel_event.is_set():
                    break
                
                if 0 < max_ips <= scanned_ips:
                    break
                
                ip_int = ip_targets.get_ip(ip_index)
                ip_str = str(ipaddress.IPv4Address(ip_int))
                
                if scan_mode == "icmp":
                    # ICMP: one task per IP, no port iteration
                    while not cancel_event.is_set():
                        try:
                            task_queue.put(ip_str, timeout=0.1)
                            break
                        except queue.Full:
                            continue
                else:
                    for port in ports:
                        if cancel_event.is_set():
                            break
                        
                        while not cancel_event.is_set():
                            try:
                                task_queue.put((ip_str, port), timeout=0.1)
                                break
                            except queue.Full:
                                continue
                            
                scanned_ips += 1
                            
            # wait for task_queue to be depleted or cancellation
            while not cancel_event.is_set() and not task_queue.empty():
                time.sleep(0.1)
                
            if not cancel_event.is_set():
                # signal threads to exit gracefully
                for _ in range(num_threads):
                    while not cancel_event.is_set():
                        try:
                            task_queue.put(None, timeout=0.1)
                            break
                        except queue.Full:
                            continue
                    
                # join threads
                for t in threads:
                    while t.is_alive() and not cancel_event.is_set():
                        t.join(timeout=0.1)

    except KeyboardInterrupt:
        cancel_event.set()
        console.print("\n[bold yellow]Keyboard interrupt received! Stopping workers and saving results...[/bold yellow]")

    end_time = datetime.now()
    duration = end_time - start_time
    
    console.print(f"\n[bold green]Scan {'Interrupted' if cancel_event.is_set() else 'Completed'}![/bold green]")
    console.print(f"Time elapsed: [bold white]{duration}[/bold white]\n")
    
    with lock:
        final_results = list(results)
    
    if not final_results:
        no_results_msg = "[bold yellow]No reachable hosts found.[/bold yellow]" if scan_mode == "icmp" else "[bold yellow]No open ports found.[/bold yellow]"
        console.print(Panel(no_results_msg, border_style="yellow"))
    else:
        if scan_mode == "icmp":
            res_table = Table(title="Reachable Hosts (ICMP)", border_style="green")
            res_table.add_column("IP Address", style="cyan", justify="left")
            res_table.add_column("Delay", style="yellow", justify="center")
            res_table.add_column("Status", style="green", justify="center")
            
            final_results.sort(key=lambda x: ipaddress.IPv4Address(x[0]))
            
            limit = 100
            for ip, _, delay in final_results[:limit]:
                res_table.add_row(str(ip), f"{delay}ms", "ALIVE")
        else:
            res_table = Table(title="Open Ports Found", border_style="green")
            res_table.add_column("IP Address", style="cyan", justify="left")
            res_table.add_column("Port", style="magenta", justify="center")
            res_table.add_column("Delay", style="yellow", justify="center")
            res_table.add_column("Status", style="green", justify="center")
            
            final_results.sort(key=lambda x: (ipaddress.IPv4Address(x[0]), x[1]))
            
            limit = 100
            for ip, port, delay in final_results[:limit]:
                res_table.add_row(str(ip), str(port), f"{delay}ms", "OPEN")
        
        console.print(res_table)
        
        if len(final_results) > limit:
            console.print(f"[dim italic]... and {len(final_results) - limit} more results.[/dim italic]")
            
        save = Confirm.ask("\nDo you want to save the results to a file?", default=True)
        if save:
            save_with_delay = Confirm.ask("Do you want to include delays in the output file?", default=False)
            os.makedirs("results", exist_ok=True)
            prefix = "icmp_results" if scan_mode == "icmp" else "scan_results"
            filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join("results", os.path.basename(filename))
            with open(filepath, "w") as f:
                for res in final_results:
                    if scan_mode == "icmp":
                        if save_with_delay:
                            f.write(f"{res[0]}, {res[2]}ms\n")
                        else:
                            f.write(f"{res[0]}\n")
                    else:
                        if save_with_delay:
                            f.write(f"{res[0]}:{res[1]}, {res[2]}ms\n")
                        else:
                            f.write(f"{res[0]}:{res[1]}\n")
            console.print(f"[green]✔[/green] Results saved to [bold white]{filepath}[/bold white]")
        
        # --- Follow-up Recheck: only after TCP scan with results ---
        if scan_mode == "tcp" and final_results:
            console.print()
            console.print("[cyan]➜[/cyan] [bold]Recheck Results[/bold]")
            console.print("  [yellow]1[/yellow]. TLS Handshake [dim](verify TLS/HTTP on found IP:port pairs)[/dim]")
            console.print("  [yellow]2[/yellow]. ICMP Ping [dim](check if found IPs are alive)[/dim]")
            console.print("  [yellow]3[/yellow]. Skip [dim](done)[/dim]")
            recheck_choice = Prompt.ask("Recheck found results?", choices=["1", "2", "3"], default="3")
            
            if recheck_choice in ("1", "2"):
                recheck_mode = "handshake" if recheck_choice == "1" else "icmp"
                recheck_label = "TLS Handshake" if recheck_mode == "handshake" else "ICMP Ping"
                
                console.print(f"\n[cyan]➜[/cyan] [bold]Recheck Configuration ({recheck_label})[/bold]")
                rc_threads = IntPrompt.ask("Number of threads", default=100 if recheck_mode == "icmp" else 500)
                rc_timeout = float(Prompt.ask("Timeout (seconds)", default="2.0" if recheck_mode == "icmp" else "1.0"))
                
                # Build unique targets from TCP results
                if recheck_mode == "handshake":
                    recheck_targets = [(ip, port) for ip, port, _ in final_results]
                else:
                    # ICMP: unique IPs only
                    seen_ips = set()
                    recheck_targets = []
                    for ip, port, _ in final_results:
                        if ip not in seen_ips:
                            seen_ips.add(ip)
                            recheck_targets.append(ip)
                
                total_recheck = len(recheck_targets)
                console.print(f"[green]✔[/green] Rechecking [bold white]{total_recheck:,}[/bold white] {'IP:port pairs' if recheck_mode == 'handshake' else 'unique IPs'} with {recheck_label}")
                console.print()
                
                rc_queue = queue.Queue(maxsize=1_000_000)
                rc_results = []
                rc_lock = threading.Lock()
                rc_threads_list = []
                rc_cancel = threading.Event()
                
                try:
                    unit_label = "ip" if recheck_mode == "icmp" else "target"
                    with rtqdm(total=total_recheck, desc=f"[magenta]Rechecking ({recheck_label})[/magenta]", unit=unit_label) as rc_pbar:
                        if recheck_mode == "icmp":
                            for _ in range(rc_threads):
                                t = threading.Thread(target=icmp_worker, args=(rc_queue, rc_timeout, rc_results, rc_lock, rc_pbar, rc_cancel), daemon=True)
                                t.start()
                                rc_threads_list.append(t)
                            for ip_str in recheck_targets:
                                while not rc_cancel.is_set():
                                    try:
                                        rc_queue.put(ip_str, timeout=0.1)
                                        break
                                    except queue.Full:
                                        continue
                        else:
                            for _ in range(rc_threads):
                                t = threading.Thread(target=worker, args=(rc_queue, rc_timeout, rc_results, rc_lock, rc_pbar, rc_cancel, "handshake"), daemon=True)
                                t.start()
                                rc_threads_list.append(t)
                            for target in recheck_targets:
                                while not rc_cancel.is_set():
                                    try:
                                        rc_queue.put(target, timeout=0.1)
                                        break
                                    except queue.Full:
                                        continue
                        
                        while not rc_cancel.is_set() and not rc_queue.empty():
                            time.sleep(0.1)
                        
                        if not rc_cancel.is_set():
                            for _ in range(rc_threads):
                                while not rc_cancel.is_set():
                                    try:
                                        rc_queue.put(None, timeout=0.1)
                                        break
                                    except queue.Full:
                                        continue
                            for t in rc_threads_list:
                                while t.is_alive() and not rc_cancel.is_set():
                                    t.join(timeout=0.1)
                
                except KeyboardInterrupt:
                    rc_cancel.set()
                    console.print("\n[bold yellow]Recheck interrupted! Showing partial results...[/bold yellow]")
                
                with rc_lock:
                    rc_final = list(rc_results)
                
                console.print(f"\n[bold green]Recheck {'Interrupted' if rc_cancel.is_set() else 'Completed'}![/bold green]")
                console.print(f"Passed: [bold white]{len(rc_final)}[/bold white] / {total_recheck}\n")
                
                if not rc_final:
                    console.print(Panel("[bold yellow]No results passed the recheck.[/bold yellow]", border_style="yellow"))
                else:
                    if recheck_mode == "icmp":
                        rc_table = Table(title=f"Recheck Results ({recheck_label})", border_style="green")
                        rc_table.add_column("IP Address", style="cyan", justify="left")
                        rc_table.add_column("Delay", style="yellow", justify="center")
                        rc_table.add_column("Status", style="green", justify="center")
                        rc_final.sort(key=lambda x: ipaddress.IPv4Address(x[0]))
                        limit = 100
                        for ip, _, delay in rc_final[:limit]:
                            rc_table.add_row(str(ip), f"{delay}ms", "ALIVE")
                    else:
                        rc_table = Table(title=f"Recheck Results ({recheck_label})", border_style="green")
                        rc_table.add_column("IP Address", style="cyan", justify="left")
                        rc_table.add_column("Port", style="magenta", justify="center")
                        rc_table.add_column("Delay", style="yellow", justify="center")
                        rc_table.add_column("Status", style="green", justify="center")
                        rc_final.sort(key=lambda x: (ipaddress.IPv4Address(x[0]), x[1]))
                        limit = 100
                        for ip, port, delay in rc_final[:limit]:
                            rc_table.add_row(str(ip), str(port), f"{delay}ms", "VERIFIED")
                    
                    console.print(rc_table)
                    if len(rc_final) > limit:
                        console.print(f"[dim italic]... and {len(rc_final) - limit} more results.[/dim italic]")
                    
                    rc_save = Confirm.ask("\nDo you want to save the recheck results to a file?", default=True)
                    if rc_save:
                        rc_save_delay = Confirm.ask("Do you want to include delays in the output file?", default=False)
                        os.makedirs("results", exist_ok=True)
                        rc_prefix = "recheck_icmp" if recheck_mode == "icmp" else "recheck_handshake"
                        rc_filename = f"{rc_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        rc_filepath = os.path.join("results", os.path.basename(rc_filename))
                        with open(rc_filepath, "w") as f:
                            for res in rc_final:
                                if recheck_mode == "icmp":
                                    if rc_save_delay:
                                        f.write(f"{res[0]}, {res[2]}ms\n")
                                    else:
                                        f.write(f"{res[0]}\n")
                                else:
                                    if rc_save_delay:
                                        f.write(f"{res[0]}:{res[1]}, {res[2]}ms\n")
                                    else:
                                        f.write(f"{res[0]}:{res[1]}\n")
                        console.print(f"[green]✔[/green] Recheck results saved to [bold white]{rc_filepath}[/bold white]")

def fetch_ips_tool():
    console.print("\n[bold cyan]--- Fetch IPs by ASN or Country Code ---[/bold cyan]")
    console.print("1. Fetch by Country Code (e.g., IR, US)")
    console.print("2. Fetch by ASN (e.g., AS15169 for Google)")
    
    choice = Prompt.ask("Select an option", choices=["1", "2"])
    
    if choice == "1":
        console.print("\n[dim]Popular: IR (Iran), US (United States), DE (Germany), CN (China)[/dim]")
        cc = Prompt.ask("[bold green]Enter Country Code[/bold green]").strip().upper()
        if not cc:
            console.print("[red]Invalid country code.[/red]")
            return
            
        url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={cc}"
        console.print(f"[blue]Fetching from RIPE stat API for country {cc}...[/blue]")
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                
            ipv4_list = data.get('data', {}).get('resources', {}).get('ipv4', [])
            
            if not ipv4_list:
                console.print(f"[yellow]No IPv4 prefixes found for country {cc}.[/yellow]")
                return
                
            console.print(f"[green]✔[/green] Found [bold]{len(ipv4_list)}[/bold] IPv4 prefixes.")
            
            default_filename = f"{cc}_ips.txt"
            filename = Prompt.ask("Save to file", default=default_filename)
            
            os.makedirs("custom_ranges", exist_ok=True)
            filepath = os.path.join("custom_ranges", os.path.basename(filename))
            with open(filepath, "w") as f:
                for prefix in ipv4_list:
                    f.write(f"{prefix}\n")
                    
            console.print(f"[green]Saved successfully to {filepath}![/green]\n")
        except Exception as e:
            console.print(f"[red]Error fetching data: {e}[/red]\n")
            
    elif choice == "2":
        console.print("\n[dim]Examples: AS32324, AS58224, 15169 (Comma separated)[/dim]")
        asn_input = Prompt.ask("[bold green]Enter ASN(s) (with or without 'AS' prefix)[/bold green]").strip()
        if not asn_input: return
        
        asns = [x.strip().upper() for x in asn_input.split(',') if x.strip()]
        if not asns: return
        
        # Use first ASN for the default filename, or a generic one if multiple
        default_filename = f"{asns[0]}_ips.txt" if len(asns) == 1 else "asns_ips.txt"
        filename = Prompt.ask("Save to file", default=default_filename)
        
        os.makedirs("custom_ranges", exist_ok=True)
        filepath = os.path.join("custom_ranges", os.path.basename(filename))
        
        all_ips = []
        for asn in asns:
            if not asn.startswith("AS"):
                asn = "AS" + asn
                
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
            console.print(f"[blue]Fetching from RIPE stat API for {asn}...[/blue]")
            
            try:
                # We'll use subprocess to run curl then regex, to mirror the exact requested behavior natively
                import subprocess, re
                result = subprocess.run(["curl", "-s", url], capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout.strip():
                    text = result.stdout
                else:
                    # Fallback to urllib if curl fails or isn't available
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        text = response.read().decode()
                
                # Extract only IPv4 addresses using regex, analogous to grep -Eo
                ipv4_list = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}', text)
                
                # Remove duplicates while preserving order
                ipv4_list = list(dict.fromkeys(ipv4_list))
                
                if not ipv4_list:
                    console.print(f"[yellow]No IPv4 prefixes found for {asn}.[/yellow]")
                    continue
                    
                console.print(f"[green]✔[/green] Found [bold]{len(ipv4_list)}[/bold] IPv4 prefixes for {asn}.")
                all_ips.extend(ipv4_list)
                
            except Exception as e:
                console.print(f"[red]Error fetching data for {asn}: {e}[/red]\n")
                
        if all_ips:
            try:
                # appending/writing all results
                with open(filepath, "w") as f:
                    for prefix in all_ips:
                        f.write(f"{prefix}\n")
                console.print(f"[green]Saved {len(all_ips)} total prefixes successfully to {filepath}![/green]\n")
            except Exception as e:
                console.print(f"[red]Error saving to file: {e}[/red]\n")

def evaluate_dns_tunneling(ip_str, domain, float_timeout):
    score = 0
    results = {
        "udp": False,
        "tcp": False,
        "recursion": False,
        "txt": False,
        "null": False,
        "edns": False,
        "cache_bust": False
    }
    
    if not HAS_DNS:
        return 0, results

    def rand_subdomain():
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "." + domain

    q_udp = dns.message.make_query(domain, dns.rdatatype.A)
    try:
        r_udp = dns.query.udp(q_udp, ip_str, timeout=float_timeout)
        if r_udp:
            results["udp"] = True
            score += 10
    except Exception:
        pass
        
    q_tcp = dns.message.make_query(domain, dns.rdatatype.A)
    try:
        r_tcp = dns.query.tcp(q_tcp, ip_str, timeout=float_timeout)
        if r_tcp:
            results["tcp"] = True
            score += 10
    except Exception:
        pass

    if not results["udp"] and not results["tcp"]:
        return score, results

    try:
        cur_sub = rand_subdomain()
        q_rec = dns.message.make_query(cur_sub, dns.rdatatype.A)
        r_rec = dns.query.udp(q_rec, ip_str, timeout=float_timeout)
        
        if r_rec and r_rec.rcode() not in [dns.rcode.REFUSED, dns.rcode.SERVFAIL]:
            results["recursion"] = True
            score += 40
            
            try:
                cur_sub2 = rand_subdomain()
                q_rec2 = dns.message.make_query(cur_sub2, dns.rdatatype.A)
                r_rec2 = dns.query.udp(q_rec2, ip_str, timeout=float_timeout)
                if r_rec2 and r_rec2.rcode() not in [dns.rcode.REFUSED, dns.rcode.SERVFAIL]:
                    results["cache_bust"] = True
                    score += 10
            except Exception:
                pass
                
            try:
                q_txt = dns.message.make_query(cur_sub, dns.rdatatype.TXT)
                r_txt = dns.query.udp(q_txt, ip_str, timeout=float_timeout)
                if r_txt and r_txt.rcode() != dns.rcode.FORMERR:
                    results["txt"] = True
                    score += 10
            except Exception:
                pass
                
            try:
                q_null = dns.message.make_query(cur_sub, dns.rdatatype.NULL)
                r_null = dns.query.udp(q_null, ip_str, timeout=float_timeout)
                if r_null and r_null.rcode() != dns.rcode.FORMERR:
                    results["null"] = True
                    score += 10
            except Exception:
                pass
                
            try:
                q_edns = dns.message.make_query(cur_sub, dns.rdatatype.A)
                q_edns.use_edns(edns=0, payload=4096)
                r_edns = dns.query.udp(q_edns, ip_str, timeout=float_timeout)
                if r_edns and r_edns.rcode() != dns.rcode.FORMERR:
                    results["edns"] = True
                    score += 10
            except Exception:
                pass

    except Exception:
        pass

    return score, results

def dns_worker(task_queue, domain, timeout, results_list, lock, pbar, cancel_event):
    while not cancel_event.is_set():
        try:
            target = task_queue.get(timeout=0.5)
        except queue.Empty:
            continue
            
        if target is None:
            task_queue.task_done()
            break
            
        ip_str = target
        score, run_results = evaluate_dns_tunneling(ip_str, domain, timeout)
        
        if score > 0:
            with lock:
                results_list.append((ip_str, score, run_results))
                count = len(results_list)
                pbar.set_postfix_str(f"✔ {count} | {ip_str} (score:{score})", refresh=False)
            
        if not cancel_event.is_set():
            pbar.update(1)
        task_queue.task_done()

def dns_scanner_tool():
    if not HAS_DNS:
        console.print("[bold red]dnspython library is missing. Please run `pip install -r requirements.txt`[/bold red]")
        return

    console.print("\n[bold cyan]--- Evaluate IPs for DNS Tunneling ---[/bold cyan]")
    
    console.print("[cyan]➜[/cyan] [bold]Enter IP targets[/bold] (comma separated IPs, CIDRs, ranges, or .txt files).")
    console.print("  [dim]Leave empty or type 'cloudflare' for Cloudflare IP ranges.[/dim]")
    ip_input = ask_with_folder_choices("IP Ranges", ["ip_ranges", "custom_ranges"], default="cloudflare")
    networks = parse_ip_input(ip_input)
    
    ip_targets = IPTargets(networks)
    if ip_targets.total == 0:
        console.print("[bold red]No valid IP address targets provided. Going back.[/bold red]")
        return
        
    console.print(f"[green]✔[/green] Loaded [bold white]{ip_targets.total:,}[/bold white] total IPs to scan.")

    console.print("\n[cyan]➜[/cyan] [bold]Enter your NS record / Tunneling Domain[/bold] (e.g. tunnel.example.com)")
    domain = Prompt.ask("[bold green]Domain[/bold green]")
    if not domain.strip():
        console.print("[bold red]Domain is required. Going back.[/bold red]")
        return

    console.print("\n[cyan]➜[/cyan] [bold]Scan Configuration[/bold]")
    num_threads = IntPrompt.ask("Number of threads", default=500)
    timeout = float(Prompt.ask("DNS Timeout (seconds)", default="2.0"))
    is_random = Confirm.ask("Randomize IP search order?", default=True)
    
    max_ips = 0
    if is_random and ip_targets.total > 10:
        limit_input = Prompt.ask("Max IPs to scan (leave empty for no limit)", default="")
        limit_clean = limit_input.strip().replace('_', '').replace(',', '')
        if limit_clean.isdigit():
            max_ips = int(limit_clean)

    console.print()

    search_ips_count = ip_targets.total
    if 0 < max_ips < ip_targets.total:
        search_ips_count = max_ips
        
    total_targets = search_ips_count
    
    table = Table(title="DNS Tunneling Scan Config", title_style="bold magenta", border_style="cyan")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Total Available IPs", f"{ip_targets.total:,}")
    if 0 < max_ips < ip_targets.total:
        table.add_row("Scanning IPs Limit", f"{max_ips:,}")
    table.add_row("Tunneling Domain", domain)
    table.add_row("Total Tasks", f"{total_targets:,}")
    table.add_row("Threads", str(num_threads))
    table.add_row("Timeout", f"{timeout}s")
    table.add_row("Search Order", "Randomized (LCG)" if is_random else "Sequential")
    
    console.print(table)
    console.print()

    if total_targets > 100_000 and not is_random:
        console.print("[bold yellow]⚠ Warning: You are initiating a sequential scan over 100k IPs![/bold yellow]")
        if not Confirm.ask("Do you want to proceed?"):
            console.print("[bold red]Scan aborted by user.[/bold red]")
            return

    task_queue = queue.Queue(maxsize=1_000_000)
    results_list = []
    lock = threading.Lock()
    threads = []
    cancel_event = threading.Event()
    
    console.print("[bold blue]Starting DNS Scanner... (Press Ctrl+C to stop early)[/bold blue]")
    start_time = datetime.now()
    
    try:
        with rtqdm(total=total_targets, desc="[magenta]Scanning DNS[/magenta]", unit="ip") as pbar:
            for _ in range(num_threads):
                t = threading.Thread(target=dns_worker, args=(task_queue, domain, timeout, results_list, lock, pbar, cancel_event), daemon=True)
                t.start()
                threads.append(t)
                
            if is_random:
                ip_gen = random_ip_indices_lcg(ip_targets.total)
            else:
                ip_gen = sequential_ip_indices(ip_targets.total)

            scanned_ips = 0
            for ip_index in ip_gen:
                if cancel_event.is_set():
                    break
                
                if 0 < max_ips <= scanned_ips:
                    break
                
                ip_int = ip_targets.get_ip(ip_index)
                ip_str = str(ipaddress.IPv4Address(ip_int))
                
                while not cancel_event.is_set():
                    try:
                        task_queue.put(ip_str, timeout=0.1)
                        break
                    except queue.Full:
                        continue
                        
                scanned_ips += 1
                
            while not cancel_event.is_set() and not task_queue.empty():
                time.sleep(0.1)
                
            if not cancel_event.is_set():
                for _ in range(num_threads):
                    while not cancel_event.is_set():
                        try:
                            task_queue.put(None, timeout=0.1)
                            break
                        except queue.Full:
                            continue
                    
                for t in threads:
                    while t.is_alive() and not cancel_event.is_set():
                        t.join(timeout=0.1)

    except KeyboardInterrupt:
        cancel_event.set()
        console.print("\n[bold yellow]Keyboard interrupt received! Stopping workers and saving results...[/bold yellow]")

    end_time = datetime.now()
    duration = end_time - start_time
    
    console.print(f"\n[bold green]Scan {'Interrupted' if cancel_event.is_set() else 'Completed'}![/bold green]")
    console.print(f"Time elapsed: [bold white]{duration}[/bold white]\n")
    
    with lock:
        final_results = list(results_list)
    
    if not final_results:
        console.print(Panel("[bold yellow]No valid resolving IPs found.[/bold yellow]", border_style="yellow"))
    else:
        res_table = Table(title="DNS Tunneling IPs Found", border_style="green")
        res_table.add_column("IP Address", style="cyan", justify="left")
        res_table.add_column("Score", style="yellow", justify="center")
        res_table.add_column("UDP/TCP", style="magenta", justify="center")
        res_table.add_column("Recursion", style="green", justify="center")
        res_table.add_column("TXT", style="blue", justify="center")
        res_table.add_column("NULL", style="blue", justify="center")
        res_table.add_column("EDNS0", style="magenta", justify="center")
        res_table.add_column("C-Bust", style="magenta", justify="center")
        
        final_results.sort(key=lambda x: x[1], reverse=True)
        
        limit = 100
        for ip_str, score, res in final_results[:limit]:
            ut = f"{'U' if res['udp'] else '-'}/{'T' if res['tcp'] else '-'}"
            rec = "✓" if res['recursion'] else "✗"
            txt = "✓" if res['txt'] else "✗"
            nl = "✓" if res['null'] else "✗"
            edns = "✓" if res['edns'] else "✗"
            cb = "✓" if res['cache_bust'] else "✗"
            
            res_table.add_row(ip_str, f"{score}/100", ut, rec, txt, nl, edns, cb)
        
        console.print(res_table)
        
        if len(final_results) > limit:
            console.print(f"[dim italic]... and {len(final_results) - limit} more results.[/dim italic]")
            
        save = Confirm.ask("\nDo you want to save the results to a file?", default=True)
        if save:
            os.makedirs("results", exist_ok=True)
            filename = f"dns_tunnel_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join("results", os.path.basename(filename))
            with open(filepath, "w") as f:
                json.dump([{"ip": ip, "score": score, "details": res} for ip, score, res in final_results], f, indent=4)
            console.print(f"[green]✔[/green] Results saved to [bold white]{filepath}[/bold white]")

def sni_worker(task_queue, timeout, results_list, lock, pbar, cancel_event):
    while not cancel_event.is_set():
        try:
            sni = task_queue.get(timeout=0.5)
        except queue.Empty:
            continue
            
        if sni is None:
            task_queue.task_done()
            break
            
        # 1. DNS Resolve
        dns_ok, dns_d = False, -1
        ip_str = ""
        try:
            start_t = time.time()
            ip_str = socket.gethostbyname(sni)
            dns_ok = True
            dns_d = int((time.time() - start_t) * 1000)
        except: pass
        
        if not dns_ok or not ip_str:
            if not cancel_event.is_set():
                pbar.update(1)
            task_queue.task_done()
            continue
        
        # 2. ICMP
        icmp_ok, icmp_d = False, -1
        try:
            start_t = time.time()
            if os.name == 'nt':
                cmd = ["ping", "-n", "1", "-w", str(int(timeout*1000)), ip_str]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip_str]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+0.5)
            if res.returncode == 0:
                icmp_ok = True
                icmp_d = int((time.time() - start_t) * 1000)
        except: pass
        
        # 3. TCP
        tcp_ok, tcp_d = False, -1
        try:
            start_t = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip_str, 443)) == 0:
                tcp_ok = True
                tcp_d = int((time.time() - start_t) * 1000)
            sock.close()
        except: pass
        
        # 4. Handshake
        tls_ok, tls_d = False, -1
        if tcp_ok: 
            try:
                start_t = time.time()
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip_str, 443)) == 0:
                    ssl_sock = context.wrap_socket(sock, server_hostname=sni)
                    tls_ok = True
                    tls_d = int((time.time() - start_t) * 1000)
                    ssl_sock.close()
                else:
                    sock.close()
            except: pass

        if tcp_ok or icmp_ok or tls_ok:
            with lock:
                results_list.append({
                    "ip": ip_str,
                    "sni": sni,
                    "dns": (dns_ok, dns_d),
                    "icmp": (icmp_ok, icmp_d),
                    "tcp": (tcp_ok, tcp_d),
                    "tls": (tls_ok, tls_d)
                })
                total_count = len(results_list)
                tls_count = sum(1 for r in results_list if r['tls'][0])
                recent = ", ".join([f"{r['sni']}" for r in results_list[-3:]])
                pbar.set_postfix_str(f"✔ {total_count} (tls:{tls_count}) | {recent}", refresh=False)

        if not cancel_event.is_set():
            pbar.update(1)
        task_queue.task_done()

def sni_scanner_tool():
    console.print("\n[bold cyan]--- SNI Scanner ---[/bold cyan]")
    
    console.print("[cyan]➜[/cyan] [bold]Enter SNI(s) to check[/bold] (comma separated domains or .txt files)")
    console.print("  [dim]Alternatively type a filename from the 'sni' folder.[/dim]")
    sni_input = ask_with_folder_choices("SNIs/Files", "sni")
    if not sni_input.strip():
        console.print("[bold red]SNI input is required.[/bold red]")
        return
        
    snis = parse_sni_input(sni_input)
    if not snis:
        return
        
    valid_snis = [sni.strip() for sni in snis if sni.strip()]
    
    if not valid_snis:
        console.print("[bold red]No valid SNIs provided. Aborting.[/bold red]")
        return

    range_map = load_ip_ranges_map()
        
    console.print("\n[cyan]➜[/cyan] [bold]Scan Configuration[/bold]")
    num_threads = IntPrompt.ask("Number of threads", default=500)
    timeout = float(Prompt.ask("Timeout (seconds)", default="1.5"))

    total_targets = len(valid_snis)
    task_queue = queue.Queue(maxsize=1_000_000)
    results_list = []
    lock = threading.Lock()
    threads = []
    cancel_event = threading.Event()
    
    for sni in valid_snis:
        task_queue.put(sni)
        
    start_time = datetime.now()
    console.print()
    
    try:
        with rtqdm(total=total_targets, desc="[magenta]Scanning SNI[/magenta]", unit="domain") as pbar:
            for _ in range(num_threads):
                t = threading.Thread(target=sni_worker, args=(task_queue, timeout, results_list, lock, pbar, cancel_event), daemon=True)
                t.start()
                threads.append(t)
                
            while not cancel_event.is_set() and not task_queue.empty():
                time.sleep(0.1)
                
            if not cancel_event.is_set():
                for _ in range(num_threads):
                    while not cancel_event.is_set():
                        try:
                            task_queue.put(None, timeout=0.1)
                            break
                        except queue.Full: continue
                    
                for t in threads:
                    while t.is_alive() and not cancel_event.is_set(): t.join(timeout=0.1)

    except KeyboardInterrupt:
        cancel_event.set()
        
    duration = datetime.now() - start_time
    
    console.print(f"\n[bold green]Scan {'Interrupted' if cancel_event.is_set() else 'Completed'}![/bold green]")
    console.print(f"Time elapsed: [bold white]{duration}[/bold white]\n")
    
    with lock:
        final_results = list(results_list)

    if not final_results:
        console.print(Panel("[bold yellow]No valid IPs found.[/bold yellow]", border_style="yellow"))
    else:
        res_table = Table(title="SNI Scanner Results", border_style="green")
        res_table.add_column("SNI Domain", style="magenta", justify="left")
        res_table.add_column("Resolved IP", style="cyan", justify="left")
        res_table.add_column("Range", style="blue")
        res_table.add_column("DNS", justify="center")
        res_table.add_column("ICMP", justify="center")
        res_table.add_column("TCP", justify="center")
        res_table.add_column("Handshake", justify="center")
        
        final_results.sort(key=lambda x: (
            x['tls'][1] if x['tls'][0] else 99999,
            x['tcp'][1] if x['tcp'][0] else 99999
        ))
        
        def fmt(res_tuple):
            ok, d = res_tuple
            return f"[green]✔ {d}ms[/green]" if ok else "[red]✗[/red]"

        limit = 100
        for res in final_results[:limit]:
            ip = res["ip"]
            sni = res["sni"]
            rng = get_ip_range_name(ip, range_map)
            res_table.add_row(sni, ip, rng, fmt(res["dns"]), fmt(res["icmp"]), fmt(res["tcp"]), fmt(res["tls"]))
            
        console.print(res_table)
        if len(final_results) > limit:
            console.print(f"[dim italic]... and {len(final_results) - limit} more results.[/dim italic]")
            
        save = Confirm.ask("\nDo you want to save the results to a file?", default=True)
        if save:
            os.makedirs("results", exist_ok=True)
            filename = f"sni_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join("results", os.path.basename(filename))
            with open(filepath, "w") as f:
                json.dump(final_results, f, indent=4)
            console.print(f"[green]✔[/green] Results saved to [bold white]{filepath}[/bold white]")

def main():
    display_banner()
    while True:
        console.print("\n[bold cyan]--- Main Menu ---[/bold cyan]")
        console.print("1. Multi-threaded IP Scanner")
        console.print("2. Fetch IPs by ASN / Country Code")
        console.print("3. Evaluate IPs for DNS Tunneling")
        console.print("4. SNI Scanner")
        console.print("5. Exit")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            scanner_tool()
        elif choice == "2":
            fetch_ips_tool()
        elif choice == "3":
            dns_scanner_tool()
        elif choice == "4":
            sni_scanner_tool()
        elif choice == "5":
            console.print("[dim]Exiting... Goodbye![/dim]")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Exiting... Goodbye![/dim]")
        sys.exit(0)
