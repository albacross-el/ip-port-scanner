from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import socket
import sys
import time

# Enable ANSI escape sequences in Windows CMD
os.system("")

# Color palette for Windows CMD
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    clear_screen()
    print(f"{CYAN}{BOLD}")
    print(r"  ___  ___  ___ _____   ___  ___  ___  _  _ _  _ ___ ___ ")
    print(r" | _ \/ _ \| _ |_   _| / __|/ __|/ _ \| \| | \| | __| _ \ ")
    print(r" |  _/ (_) |   / | |   \__ \ (__| /_\ | .` | .` | _||   / ")
    print(r" |_|  \___/|_|_\ |_|   |___/\___|__|__|_|\_|_|\_|___|_|_\ ")
    print(f"{RESET}")
    print(f"{YELLOW}   [TCP Connect Scanner - eaglesoft]{RESET}\n")


def resolve_host(target: str) -> tuple[str, str]:
    """Resolves a hostname/domain or IP address."""
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror:
        return target, ""


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Attempts to pull banner info from open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in [80, 8080, 443, 8443]:
                s.sendall(
                    b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
                )

            banner = s.recv(512).decode(errors="ignore").strip()
            # Clean newlines for CMD tabular display
            banner = banner.replace("\r", " ").replace("\n", " ")
            return banner[:35] + "..." if len(banner) > 35 else banner
    except Exception:
        return "No banner"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Scans a single port via standard TCP connect."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_SERVICES.get(port)
                if not service:
                    try:
                        service = socket.getservbyport(port, "tcp").upper()
                    except OSError:
                        service = "UNKNOWN"

                banner = grab_banner(ip, port, timeout)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner if banner else "No response",
                }
    except Exception:
        pass
    return None


def select_ports_menu() -> list[int]:
    """Interactive port selection menu."""
    print(f"{BOLD}Select Port Range:{RESET}")
    print(" [1] Top Common Ports (15 common web/database/remote ports)")
    print(" [2] Standard Well-Known Ports (1 - 1024)")
    print(" [3] Custom Port Range (e.g., 20-100)")
    print(" [4] Specific Custom Ports (e.g., 80,443,3389)")

    choice = input(f"\n{CYAN}Select option [1-4]: {RESET}").strip()

    if choice == "1":
        return sorted(list(COMMON_SERVICES.keys()))
    elif choice == "2":
        return list(range(1, 1025))
    elif choice == "3":
        try:
            rng = input(f"{CYAN}Enter range (e.g., 1-500): {RESET}").strip()
            start, end = map(int, rng.split("-"))
            return list(range(start, end + 1))
        except ValueError:
            print(f"{RED}Invalid range format. Defaulting to Top Common Ports.{RESET}")
            return sorted(list(COMMON_SERVICES.keys()))
    elif choice == "4":
        try:
            raw = input(f"{CYAN}Enter ports separated by commas: {RESET}").strip()
            return [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
        except ValueError:
            print(f"{RED}Invalid input. Defaulting to Top Common Ports.{RESET}")
            return sorted(list(COMMON_SERVICES.keys()))
    else:
        return sorted(list(COMMON_SERVICES.keys()))


def save_results_to_file(target: str, ip: str, results: list):
    """Saves scan results to a plain text file."""
    filename = f"scan_{ip.replace('.', '_')}.txt"
    try:
        with open(filename, "w") as f:
            f.write(f"PORT SCAN REPORT - TARGET: {target} ({ip})\n")
            f.write("=" * 65 + "\n")
            f.write(f"{'PORT':<10} {'SERVICE':<15} {'BANNER'}\n")
            f.write("-" * 65 + "\n")
            for r in results:
                f.write(f"{r['port']:<10} {r['service']:<15} {r['banner']}\n")
        print(f"\n{GREEN}[+] Results successfully saved to: {filename}{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Failed to save file: {e}{RESET}")


def run_app():
    last_results = []
    last_target = ""
    last_ip = ""

    while True:
        print_banner()
        print(f"{BOLD}Main Menu:{RESET}")
        print(" [1] Start New Scan")
        print(" [2] Export Last Scan Results")
        print(" [3] Exit")

        main_choice = input(f"\n{CYAN}Select option [1-3]: {RESET}").strip()

        if main_choice == "1":
            print_banner()
            target_input = input(
                f"{CYAN}Enter Target Hostname or IP (e.g., 127.0.0.1 or scanme.nmap.org): {RESET}"
            ).strip()
            if not target_input:
                continue

            host, ip = resolve_host(target_input)
            if not ip:
                print(f"{RED}[!] Error: Could not resolve hostname '{target_input}'.{RESET}")
                input("\nPress Enter to return to main menu...")
                continue

            print(f"{GREEN}[+] Resolved target '{host}' to IP: {ip}{RESET}\n")

            ports = select_ports_menu()

            # Speed settings
            threads_input = input(
                f"{CYAN}Enter Max Threads [Default 50]: {RESET}"
            ).strip()
            threads = int(threads_input) if threads_input.isdigit() else 50

            # Execute Scan
            print(
                f"\n{YELLOW}[*] Scanning {len(ports)} ports on {ip} using {threads} threads...{RESET}\n"
            )
            print(f"{BOLD}{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER':<35}{RESET}")
            print("-" * 70)

            open_results = []
            start_time = time.time()

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(scan_port, ip, port): port for port in ports
                }
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        open_results.append(res)
                        print(
                            f"{GREEN}{res['port']:<10}{RESET} "
                            f"{GREEN}{'OPEN':<10}{RESET} "
                            f"{CYAN}{res['service']:<15}{RESET} "
                            f"{res['banner']:<35}"
                        )

            elapsed = time.time() - start_time
            open_results = sorted(open_results, key=lambda x: x["port"])

            last_results = open_results
            last_target = host
            last_ip = ip

            print("-" * 70)
            print(
                f"{GREEN}[+] Scan complete in {elapsed:.2f}s. Found {len(open_results)} open ports.{RESET}"
            )
            input("\nPress Enter to return to main menu...")

        elif main_choice == "2":
            if not last_results:
                print(f"\n{RED}[!] No recent scan results available to save.{RESET}")
            else:
                save_results_to_file(last_target, last_ip, last_results)
            input("\nPress Enter to return to main menu...")

        elif main_choice == "3":
            print(f"\n{YELLOW}Exiting scanner. Goodbye!{RESET}")
            sys.exit(0)


if __name__ == "__main__":
    try:
        run_app()
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] User interrupted execution. Exiting.{RESET}")
        sys.exit(0)
