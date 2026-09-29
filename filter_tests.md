# Firewall Filter Tests

## Network Configuration

| Parameter | Value |
|---|---|
| Records Server / Test Host | `192.168.1.70` |
| Local/Staff Network | `192.168.1.0/24` |
| Default Gateway | `192.168.1.254` |
| Simulated Guest Network | `192.168.2.0/24` |
| Service | Student Records Application |
| Protocol | TCP |
| Service Port | `8443` |

## Test 1 – Permitted Staff Connection

- Source: `192.168.1.50`
- Destination: `192.168.1.70`
- Protocol: TCP
- Port: `8443`
- Expected: `ACCEPT`
- Actual: `ACCEPT`
- Status: **PASS**

## Test 2 – Blocked Guest Connection

- Source: `192.168.2.75`
- Destination: `192.168.1.70`
- Protocol: TCP
- Port: `8443`
- Expected: `DROP`
- Actual: `DROP`
- Status: **PASS**

## Test 3 – Blocked External Connection

- Source: `203.0.113.50`
- Destination: `192.168.1.70`
- Protocol: TCP
- Port: `8443`
- Expected: `DROP`
- Actual: `DROP`
- Status: **PASS**

## Overall Result

All three firewall simulation tests passed.

The tests were executed using `firewall_simulator.py` on Windows 11. The
simulated guest network was used because no separate guest network was
available on the computer. The Linux `iptables` equivalent is documented in
`firewall_rules.sh` and was not executed on Windows 11.

## Reproduction Command

```powershell
python firewall_simulator.py