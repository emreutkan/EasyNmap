import os
import sys

from colorama import Fore, Style
import subprocess

OPERATING_SYSTEM = os.name

def get_machine_ip():
    if OPERATING_SYSTEM == 'posix':
        return os.popen('hostname -I').read().split()[0]
    else:
        return " "
def clear():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def validate_ip(target):
    """
    Check if the target IP address is valid

    :param target: target IP address
    """
    parts = target.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not 0 <= int(part) <= 255:
            return False
    return True

def validate_port(port):
    """
    Check if the port or port range is valid
    """
    try:
        if 1 <= int(port) <= 65535:
            return True
    except ValueError:
        if (0 <= int(port.split("-")[0]) <= 65535
                and 0 <= int(port.split("-")[1]) <= 65535
                and int(port.split("-")[0]) < int(port.split("-")[1])):
            return True
    return False

TARGET_IP = os.popen('hostname -I').read().split()[0] if os.name == 'posix' else " "
VERBOSE = False
VULN_SCAN = False
AGGRESSIVE_SCAN = False
OS_DETECTION = False
timing = 3
PORT_RANGE = "1-1000"
PING_SCAN = False
DECOY_SCAN = False
DECOY_COUNT = 5
SPOOF_MAC = False
VERSION_DETECTION = False
USE_INTERFACE = False
INTERFACE = ""
FRAGMENT_PACKETS = False
TRACEROUTE = False


# def getch():
#     """Gets a single character from standard input, does not echo to the screen."""
#     fd = sys.stdin.fileno()
#     old_settings = termios.tcgetattr(fd)
#     try:
#         tty.setraw(sys.stdin.fileno())
#         ch = sys.stdin.read(1)
#     finally:
#         termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
#     return ch


def toggle_interface():
    """
    Turn on/off interface
    """
    global USE_INTERFACE
    global INTERFACE
    USE_INTERFACE = not USE_INTERFACE
    if USE_INTERFACE:
        select_interface()


def toggle_verbose():
    """
    Turn on/off verbose
    """
    global VERBOSE
    VERBOSE = not VERBOSE
    print(f"Verbose: {VERBOSE}")


def toggle_fragment_packets():
    """
    Turn on/off fragment packets
    """
    global FRAGMENT_PACKETS
    FRAGMENT_PACKETS = not FRAGMENT_PACKETS


def toggle_vulnerability_scan():
    """
    Turn on/off vulnerability scan
    """
    global VULN_SCAN
    VULN_SCAN = not VULN_SCAN


def toggle_version_detection():
    """
    Turn on/off version detection
    """
    global VERSION_DETECTION
    global AGGRESSIVE_SCAN
    VERSION_DETECTION = not VERSION_DETECTION
    if VERSION_DETECTION:
        AGGRESSIVE_SCAN = False


def set_timing():
    """
    Set the timing for the scan
    """
    global timing
    timing = input("Enter the timing (0-5): ")
    if not 0 <= int(timing) <= 5:
        print("Invalid timing")
        set_timing()


def toggle_traceroute():
    """
    Turn on/off traceroute
    """
    global TRACEROUTE
    TRACEROUTE = not TRACEROUTE


def toggle_spoof_mac():
    """
    Turn on/off MAC address spoofing

    --spoof-mac interfares with the -D option
    """
    global SPOOF_MAC
    global DECOY_SCAN
    SPOOF_MAC = not SPOOF_MAC
    if SPOOF_MAC:
        DECOY_SCAN = False


def toggle_ping_scan():
    """
    Turn on/off ping scan
    """
    global PING_SCAN
    PING_SCAN = not PING_SCAN


def toggle_aggressive_scan():
    """
    -A = -O, -sV, --traceroute, --script=default
    Using -A with explicit calls to -O, -sV, --traceroute or --script=default does not cause conflicts but is redundant.

    :return:
    """
    global AGGRESSIVE_SCAN
    global OS_DETECTION
    global VERSION_DETECTION
    AGGRESSIVE_SCAN = not AGGRESSIVE_SCAN
    if AGGRESSIVE_SCAN:
        OS_DETECTION = False
        VERSION_DETECTION = False


def toggle_os_detection():
    """
    Turn on/off OS detection
    """
    global OS_DETECTION
    global AGGRESSIVE_SCAN
    OS_DETECTION = not OS_DETECTION
    if OS_DETECTION:
        AGGRESSIVE_SCAN = False


def set_decoy_count():
    """
    Set the number of decoys for the scan
    """
    global DECOY_COUNT
    DECOY_COUNT = input("Enter the number of decoys: ")
    if not 0 <= int(DECOY_COUNT) <= 5:
        print("Invalid number of decoys")
        set_decoy_count()


def toggle_decoy_scan():
    """
    Turn on/off decoy scan
    """
    global DECOY_SCAN
    global SPOOF_MAC
    DECOY_SCAN = not DECOY_SCAN
    if DECOY_SCAN:
        SPOOF_MAC = False
        set_decoy_count()



def select_target():
    """
    Prompt the user to select a target to scan

    :return: the target IP address
    """
    global TARGET_IP
    target = input("Enter the target IP address: ")
    if validate_ip(target):
        TARGET_IP = target
        return TARGET_IP
    else:
        print("Invalid IP address")
        select_target()


def select_interface():
    """
    Prompt the user to select an interface to use

    :return: the interface to use
    """
    global INTERFACE
    interfaces = subprocess.run("ifconfig | grep -o '^[a-zA-Z0-9]*'", shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    print(interfaces.stdout.split())
    interface = input("Enter the interface: ")
    clear()
    if interface not in interfaces.stdout.split():
        print("Invalid interface")
        select_interface()
    if not interface:
        print("Invalid interface")
        select_interface()
    INTERFACE = interface
    return INTERFACE


def set_port_range():
    """
    Set the port range for the scan
    """
    global ALL_PORTS
    global PORT_RANGE
    print("Enter the port or port range (e.g. 1-1000): ")
    print("Type 0 to scan all ports")
    port_range = input(" > ")
    if port_range == "0":
        PORT_RANGE = "1-65535"
    else:
     if validate_port(port_range):
        PORT_RANGE = port_range
     else:
        print("Invalid port or port range")
        set_port_range()


def make_command():
    command = "nmap"  # Equivalents
    command += f" -p {PORT_RANGE}" if PORT_RANGE != "1-1000" else ""
    command += " -sV" if VERSION_DETECTION else ""
    command += f" -T{timing}" if timing != 3 else ""
    command += " -Pn" if PING_SCAN else ""  # -sn
    command += " -O" if OS_DETECTION else ""
    command += " -A" if AGGRESSIVE_SCAN else ""  # -O, -sV, --traceroute, --script=default
    command += " --script=vuln" if VULN_SCAN else ""
    command += " --spoof-mac 0" if SPOOF_MAC else ""
    command += f" -D RND:{DECOY_COUNT}" if DECOY_SCAN else ""
    command += " -v" if VERBOSE else ""
    command += f" -e {INTERFACE}" if USE_INTERFACE else ""
    command += " -f" if FRAGMENT_PACKETS else ""
    command += " --traceroute" if TRACEROUTE else ""

    return command + f" {TARGET_IP}"


def display_interface():
    clear()

    # Creating a list of all options
    options = [
        ("I) Target IP", f"{Fore.BLUE}{TARGET_IP}{Style.RESET_ALL}"),
        ("P) Port Range", f"{Fore.YELLOW}{PORT_RANGE}{Style.RESET_ALL}"),
        ("T) Set Timing", f"{Fore.YELLOW}{timing}{Style.RESET_ALL}"),
        ("E) Use Interface",
         f"{Fore.GREEN if USE_INTERFACE else Fore.RED}{'ON' if USE_INTERFACE else 'OFF'}{Style.RESET_ALL}"),
        ("R) Traceroute", f"{Fore.GREEN if TRACEROUTE else Fore.RED}{'ON' if TRACEROUTE else 'OFF'}{Style.RESET_ALL}"),
        ("1) Aggressive Scan",
         f"{Fore.RED if not AGGRESSIVE_SCAN else Fore.GREEN}{'ON' if AGGRESSIVE_SCAN else 'OFF'}{Style.RESET_ALL}"),
        ("2) Fragment Packets",
         f"{Fore.GREEN if FRAGMENT_PACKETS else Fore.RED}{'ON' if FRAGMENT_PACKETS else 'OFF'}{Style.RESET_ALL}"),
        ("3) Decoy Scan",
         f"{Fore.GREEN if DECOY_SCAN else Fore.RED}{f'ON - Count : {DECOY_COUNT}' if DECOY_SCAN else 'OFF'}{Style.RESET_ALL}"),
        ("4) OS Detection",
         f"{Fore.GREEN if OS_DETECTION else Fore.RED}{'ON' if OS_DETECTION else 'OFF'}{Style.RESET_ALL}"),
        ("5) Ping Scan", f"{Fore.GREEN if PING_SCAN else Fore.RED}{'ON' if PING_SCAN else 'OFF'}{Style.RESET_ALL}"),
        ("6) Spoof MAC Address",
         f"{Fore.GREEN if SPOOF_MAC else Fore.RED}{'ON' if SPOOF_MAC else 'OFF'}{Style.RESET_ALL}"),
        ("7) Verbose Mode", f"{Fore.GREEN if VERBOSE else Fore.RED}{'ON' if VERBOSE else 'OFF'}{Style.RESET_ALL}"),
        ("8) Version Detection",
         f"{Fore.GREEN if VERSION_DETECTION else Fore.RED}{'ON' if VERSION_DETECTION else 'OFF'}{Style.RESET_ALL}"),
        ("9) Vulnerability Scan",
         f"{Fore.RED if not VULN_SCAN else Fore.GREEN}{'ON' if VULN_SCAN else 'OFF'}{Style.RESET_ALL}"),
    ]

    # Calculate the maximum length of the labels in both columns
    max_len_left_label = max(len(opt[0]) for opt in options[:len(options) // 2]) + 2  # Padding for left labels
    max_len_right_label = max(len(opt[0]) for opt in options[len(options) // 2:]) + 2  # Padding for right labels

    # Calculate the maximum length of the status in both columns to align status texts
    max_len_left_status = max(len(opt[1]) for opt in options[:len(options) // 2])
    max_len_right_status = max(len(opt[1]) for opt in options[len(options) // 2:])

    # Print options in two columns
    left_column = options[:len(options) // 2]
    right_column = options[len(options) // 2:]

    # Ensure both columns are the same length for alignment
    if len(left_column) > len(right_column):
        right_column += [("", "")] * (len(left_column) - len(right_column))
    elif len(right_column) > len(left_column):
        left_column += [("", "")] * (len(right_column) - len(left_column))

    for left, right in zip(left_column, right_column):
        left_label, left_status = left[0], left[1]
        right_label, right_status = right[0], right[1]

        # Formatting each column
        left_text = f"{left_label.ljust(max_len_left_label)}: {left_status.rjust(max_len_left_status)}"
        right_text = f"{right_label.ljust(max_len_right_label)}: {right_status.rjust(max_len_right_status)}"

        # Ensuring there is a consistent space between the two columns
        print(f"{left_text}   {right_text}")

    command = make_command()

    print(f"\nQ) Exit")
    print(f"S) Start Scan        : {Fore.BLUE}{command}{Style.RESET_ALL}")


# Make sure the 'make_command' and
def run_nmap():
    clear()
    command = make_command()
    print(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        output = process.stdout.readline()
        if process.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = process.poll()
    print(f"Scan completed with return code: {rc}")
    input("Press Enter to continue...")


def custom_nmap():
    while True:
        display_interface()

        option = input(f"{Fore.GREEN}>  ").upper()
        if option == "Q":
            return
        elif option == "I":
            select_target()
        elif option == "P":
            set_port_range()
        elif option == "T":
            set_timing()
        elif option == "E":
            toggle_interface()
        elif option == "R":
            toggle_traceroute()
        elif option == "1":
            toggle_aggressive_scan()
        elif option == "2":
            toggle_fragment_packets()
        elif option == "3":
            toggle_decoy_scan()
        elif option == "4":
            toggle_os_detection()
        elif option == "5":
            toggle_ping_scan()
        elif option == "6":
            toggle_spoof_mac()
        elif option == "7":
            toggle_verbose()
        elif option == "8":
            toggle_version_detection()
        elif option == "9":
            toggle_vulnerability_scan()
        elif option == "S":
            run_nmap()
        else:
            continue


if __name__ == "__main__":
    custom_nmap()
