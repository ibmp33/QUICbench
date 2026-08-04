import subprocess

def run_local_sudo(cmd):
    subprocess.run(["sudo", "bash", "-lc", cmd], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def delete_ingress_interface(server_hostname, server_pw_path, interface, ingress_interface):
    cmd = (
        "tc qdisc del dev {interface} handle ffff: ingress;"
        "tc qdisc del dev {ingress_interface} root;"
        "ip link set dev {ingress_interface} down;"
    ).format(interface=interface, ingress_interface=ingress_interface)
    run_local_sudo(cmd)

def delete_virtual_interface(server_hostname, server_pw_path, server_ip, interface, virtual_interface):
    cmd = (
        "ip addr add dev {interface} {server_ip}/8;"
        "ip addr flush dev {virtual_interface};"
        "ip link del dev {virtual_interface};"
    ).format(interface=interface, virtual_interface=virtual_interface, server_ip=server_ip)
    run_local_sudo(cmd)

def clear_netem(server_hostname, server_pw_path, server_ip, interface, ingress_interface, virtual_interface=None):
    print("Clearing network emulation:")
    try:
        delete_ingress_interface(server_hostname, server_pw_path, interface, ingress_interface)
    except subprocess.CalledProcessError:
        pass
    if virtual_interface:
        try:
            delete_virtual_interface(server_hostname, server_pw_path, server_ip, interface, virtual_interface)
        except subprocess.CalledProcessError:
            pass
    cmd = (
        "tc qdisc del dev {} root;"
        "tc qdisc show dev {}"
    ).format(interface, interface)
    subprocess.run(["sudo", "bash", "-lc", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
