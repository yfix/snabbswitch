#!/bin/bash

SKIPPED_CODE=43

if [ ! -f ~/bench_conf.sh ]; then
    cat <<EOF
~/bench_conf.sh does not exist, skipping test.

For this test to run you need to configure the following variables:
SNABB_LOG0=<path_to_logfile>
NFV_PCI0=<pciaddr>
NFV_SOCKET0=vhost_A.sock
NFV_SOCKET1=vhost_B.sock
GUEST_IP0=fe80::5054:ff:fe00:0
GUEST_MAC0=52:54:00:00:00:00
IMAGE0=<ubuntu-image-a>
GUEST_IP1=fe80::5054:ff:fe00:1
GUEST_MAC1=52:54:00:00:00:01
IMAGE1=<ubuntu-image-b>
BOOTARGS0="earlyprintk root=/dev/vda rw console=ttyS0 ip=$GUEST_IP0"
BOOTARGS1="earlyprintk root=/dev/vda rw console=ttyS0 ip=$GUEST_IP1"
EOF
    exit $SKIPPED_CODE
fi

. /etc/bench_conf.sh
. ~/bench_conf.sh

export BENCH_ENV_PID

# Usage: run_telnet <port> <command> [<sleep>]
# Runs <command> on VM listening on telnet <port>. Waits <sleep> seconds
# for before closing connection. The default of <sleep> is 2.
function run_telnet {
    (echo "$2"; sleep ${3:-2}) \
        | telnet localhost $1 2>&1
}

# Usage: wait_vm_up <port>
# Blocks until ping to 0::0 suceeds.
function wait_vm_up {
    echo -n "Waiting for VM listening on telnet port $1 to get ready..."
    while ( ! (run_telnet $1 "ping6 -c 1 0::0" | grep "1 received" \
        >/dev/null) ); do
        sleep 2
    done
    echo " [OK]"
}

function start_bench_env {
    scripts/bench_env/host-nic-snabbnfv-guests.sh $1 &
    BENCH_ENV_PID=$!

    # Give bench_env time to print its stuff.
    sleep 0.25

    # Wait until VMs are ready.
    wait_vm_up $TELNET_PORT0
    wait_vm_up $TELNET_PORT1
}

function stop_bench_env {
    kill $BENCH_ENV_PID

    # Give VMs and snabbnfv-traffic time to shut down.
    sleep 5
}

function assert {
    if [ $2 == "0" ]; then echo "$1 succeded."
    else echo "$1 failed."
         stop_bench_env
         exit 1
    fi
}

# Usage: debug_tcpdump <telnet_port> <n>
# Capture <n> packets on eth0 for VM listening in <telnet_port> to
# /eth0.cap.
function debug_tcpdump {
    run_telnet $1 "nohup tcpdump -c $2 -i eth0 -w /eth0.cap &"
}

# Usage: test_ping <telnet_port> <dest_ip>
# Assert successful ping from VM listening on <telnet_port> to <dest_ip>.
function test_ping {
    run_telnet $1 "ping6 -c 1 $2" \
        | grep "1 packets transmitted, 1 received"
    assert PING $?
}

# Usage: test_jumboping <telnet_port0> <telnet_port1> <dest_ip>
# Set large "jumbo" MTU to VMs listening on <telnet_port0> and
# <telnet_port1>. Assert successful jumbo ping from VM listening on
# <telnet_port0> to <dest_ip>.
function test_jumboping {
    run_telnet $1 "ip link set dev eth0 mtu 9100"
    run_telnet $2 "ip link set dev eth0 mtu 9100"
    run_telnet $1 "ping6 -s 9000 -c 1 $3" \
        | grep "1 packets transmitted, 1 received"
    assert JUMBOPING $?
}

# Usage: test_cheksum <telnet_port>
# Assert that checksum offload is negotiated on VM listening on
# <telnet_port>.
function test_checksum {
    local out=$(run_telnet $1 "ethtool -k eth0")

    echo "$out" | grep 'rx-checksumming: on'
    assert RX-CHECKSUMMING  $?

    echo "$out" | grep 'tx-checksumming: on'
    assert TX-CHECKSUMMING  $?

    echo "$out" | grep 'tx-checksum-ipv4: on'
    assert TX-CHECKSUM-IPV4 $?

    echo "$out" | grep 'rx-checksum-ipv6: on'
    assert TX-CHECKSUM-IPV6 $?
}

# Usage: test_iperf <telnet_port0> <telnet_port1> <dest_ip>
# Assert successful (whatever that means) iperf run with <telnet_port1>
# listening and <telnet_port0> sending to <dest_ip>.
function test_iperf {
    run_telnet $2 "nohup iperf -s -V &" >/dev/null
    sleep 2
    run_telnet $1 "iperf -c $3 -V" 20 \
        | grep "s/sec"
    assert IPERF $?
}

# Usage: port_probe <telnet_port0> <telnet_port1> <dest_ip> <port> [-u]
# Returns `true' if VM listening on <telnet_port0> can connect to
# <dest_ip>/<port> on VM listening on <telnet_port1>. If `-u' is appended
# UDP is used instead of TCP.
function port_probe {
    run_telnet $2 "nohup echo | nc $5 -l $3 $4 &" 2>&1 >/dev/null
    run_telnet $1 "nc -v $5 $3 $4" 5 | grep succeeded
}

function same_vlan_tests {
    start_bench_env test_fixtures/nfvconfig/test_functions/same_vlan.ports
    echo "TESTING same_vlan.ports"

    test_ping $TELNET_PORT0 "$GUEST_IP1%eth0"
    test_iperf $TELNET_PORT0 $TELNET_PORT1 "$GUEST_IP1%eth0"
#    test_jumboping $TELNET_PORT0 $TELNET_PORT1 "$GUEST_IP1%eth0"
#    test_checksum $TELNET_PORT0
#    test_checksum $TELNET_PORT1

    stop_bench_env
}

function tunnel_tests {
    start_bench_env test_fixtures/nfvconfig/test_functions/tunnel.ports
    echo "TESTING tunnel.ports"

    # Assert ND was successful.
    grep "Resolved next-hop" $SNABB_LOG0
    assert ND $?

    test_ping $TELNET_PORT0 "$GUEST_IP1%eth0"

    stop_bench_env
}

function filter_tests {
    start_bench_env test_fixtures/nfvconfig/test_functions/filter.ports
    echo "TESTING filter.ports"

    # port B allows ICMP and TCP/12345
    # The test cases were more involved at first but I found it quite
    # hard to use netcat reliably (see `port_probe'), e.g. once you
    # listen on *any* UDP port, any subsequent netcat listens will fail?!
    #
    # If you add any test cases, make *sure* that they fail without the
    # filter enabled, e.g. watch out for false negatives! I had my fair
    # share of trouble with those.
    #
    # Regards, Max Rottenkolber <max@mr.gy>

    test_ping $TELNET_PORT0 "$GUEST_IP1%eth0"

    port_probe $TELNET_PORT0 $TELNET_PORT1 "$GUEST_IP1%eth0" 12345
    assert PORTPROBE $?

    # Assert TCP/12346 is filtered.
    port_probe $TELNET_PORT0 $TELNET_PORT1 "$GUEST_IP1%eth0" 12346
    test 0 -ne $?
    assert FILTER $?

    # Assert UDP/12345 is filtered.
    port_probe $TELNET_PORT0 $TELNET_PORT1 "$GUEST_IP1%eth0" 12345 -u
    test 0 -ne $?
    assert FILTER $?

    stop_bench_env
}

# Run test configs.

same_vlan_tests
tunnel_tests
filter_tests
