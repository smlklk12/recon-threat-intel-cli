#!/usr/bin/env python3
import sys
import socket
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def get_ip_intel(target_ip):
    console.print(f"\n[bold cyan][*] Querying Threat Intelligence for:[/bold cyan] [yellow]{target_ip}[/yellow]...")
    try:
        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,regionName,city,isp,org,as,query"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "fail":
            console.print(f"[bold red][-] Error querying IP:[/bold red] {data.get('message')}")
            return None
        return data
    except Exception as e:
        console.print(f"[bold red][-] Network error:[/bold red] {e}")
        return None

def scan_target_ports(target_ip):
    common_ports = [21, 22, 80, 443, 8080]
    open_ports = []
    console.print("[bold cyan][*] Scanning common attack surface ports...[/bold cyan]")

    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def display_report(data, open_ports):
    # Summary Panel
    console.print(Panel(f"[bold green]Reconnaissance & Threat Intel Report: {data.get('query')}[/bold green]", expand=False))

    # Details Table
    table = Table(title="Host Infrastructure & Geolocation", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Details", style="white")

    table.add_row("IP Address", str(data.get("query")))
    table.add_row("Country", f"{data.get('country')} ({data.get('city')}, {data.get('regionName')})")
    table.add_row("ISP", str(data.get("isp")))
    table.add_row("Organization", str(data.get("org")))
    table.add_row("Autonomous System (ASN)", str(data.get("as")))

    ports_str = ", ".join(map(str, open_ports)) if open_ports else "None detected (Filtered / Closed)"
    table.add_row("Exposed Ports", f"[bold yellow]{ports_str}[/bold yellow]")

    console.print(table)

def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python3 recon_intel.py <IP_ADDRESS>")
        sys.exit(1)

    target_ip = sys.argv[1]
    intel_data = get_ip_intel(target_ip)

    if intel_data:
        open_ports = scan_target_ports(target_ip)
        display_report(intel_data, open_ports)

if __name__ == "__main__":
    main()
