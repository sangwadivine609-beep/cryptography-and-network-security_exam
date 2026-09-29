#!/usr/bin/env python3

"""
firewall_simulator.py

Firewall simulation adapted to the Windows 11 computer.

Actual computer/network information:
    Computer IPv4 : 192.168.1.70
    Subnet        : 192.168.1.0/24
    Gateway       : 192.168.1.254

The guest network and external host are simulated for testing.
"""

import ipaddress
import sys


# =========================================================
# NETWORK CONFIGURATION
# =========================================================

# Your Windows computer
SERVER_IP = ipaddress.ip_address("192.168.1.70")

# Student records service
SERVICE_PORT = 8443

# Your current local Wi-Fi network
STAFF_NET = ipaddress.ip_network("192.168.1.0/24")

# Simulated guest network
GUEST_NET = ipaddress.ip_network("192.168.2.0/24")


# =========================================================
# FIREWALL EVALUATION
# =========================================================

def evaluate(source_ip, destination_ip, destination_port):

    try:
        src = ipaddress.ip_address(source_ip)
        dst = ipaddress.ip_address(destination_ip)

    except ValueError as error:
        return "DROP", f"Invalid IP address: {error}"

    # -----------------------------------------------------
    # Destination must be the records server
    # -----------------------------------------------------

    if dst != SERVER_IP:
        return "DROP", "Destination is not the records server"

    # -----------------------------------------------------
    # Rule 1: Block guest network
    # -----------------------------------------------------

    if src in GUEST_NET:
        return "DROP", "Source is in the simulated guest network"

    # -----------------------------------------------------
    # Rule 2: Allow staff network to service port 8443
    # -----------------------------------------------------

    if src in STAFF_NET:

        if destination_port == SERVICE_PORT:
            return "ACCEPT", (
                "Source is in the staff network "
                "and the service port is authorised"
            )

        return "DROP", (
            "Staff network attempted to access "
            "a non-authorised port"
        )

    # -----------------------------------------------------
    # Rule 3: Block other sources from service port
    # -----------------------------------------------------

    if destination_port == SERVICE_PORT:
        return "DROP", (
            "Source is not in the authorised staff network"
        )

    # -----------------------------------------------------
    # Rule 4: Default policy
    # -----------------------------------------------------

    return "DROP", "Default firewall policy"


# =========================================================
# TEST FUNCTION
# =========================================================

def run_test(name, source_ip, destination_port, expected):

    verdict, reason = evaluate(
        source_ip,
        str(SERVER_IP),
        destination_port
    )

    passed = verdict == expected

    status = "PASS" if passed else "FAIL"

    print(f"[{status}] {name}")
    print(f"    Source      : {source_ip}")
    print(
        f"    Destination : "
        f"{SERVER_IP}:{destination_port}"
    )
    print(f"    Expected    : {expected}")
    print(f"    Actual      : {verdict}")
    print(f"    Reason      : {reason}")

    return passed


# =========================================================
# MAIN TESTS
# =========================================================

if __name__ == "__main__":

    print("=" * 65)
    print("WINDOWS 11 FIREWALL SIMULATION")
    print("=" * 65)

    print(f"Records Server : {SERVER_IP}")
    print(f"Service Port   : {SERVICE_PORT}")
    print(f"Staff Network  : {STAFF_NET}")
    print(f"Guest Network  : {GUEST_NET}")

    print("=" * 65)
    print()

    results = []

    # -----------------------------------------------------
    # TEST 1
    # Staff network -> records service
    # Expected: ACCEPT
    # -----------------------------------------------------

    results.append(
        run_test(
            "Test 1: Staff -> Records Service",
            source_ip="192.168.1.50",
            destination_port=8443,
            expected="ACCEPT"
        )
    )

    print()

    # -----------------------------------------------------
    # TEST 2
    # Guest network -> records service
    # Expected: DROP
    # -----------------------------------------------------

    results.append(
        run_test(
            "Test 2: Guest -> Records Service",
            source_ip="192.168.2.75",
            destination_port=8443,
            expected="DROP"
        )
    )

    print()

    # -----------------------------------------------------
    # TEST 3
    # External host -> records service
    # Expected: DROP
    # -----------------------------------------------------

    results.append(
        run_test(
            "Test 3: External Host -> Records Service",
            source_ip="203.0.113.50",
            destination_port=8443,
            expected="DROP"
        )
    )

    print()
    print("=" * 65)

    # -----------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------

    if all(results):

        print(f"All {len(results)} firewall tests passed.")
        sys.exit(0)

    else:

        failed = results.count(False)

        print(f"{failed} firewall test(s) failed.")
        sys.exit(1)