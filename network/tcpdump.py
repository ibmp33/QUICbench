import subprocess
import time

class TCPDump:
    """
    Represents a tcpdump instance to capture outgoing packets from server
    """

    def __init__(self, server_hostname, server_ip, interface, output_file):
        self.server_hostname = server_hostname
        self.server_ip = server_ip
        self.interface = interface
        self.output_file = output_file

    def start(self):
        self.proc = subprocess.Popen(
            ["sudo", "-n", *self.get_start_cmd()],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.3)
        if self.proc.poll() is not None:
            stderr = (self.proc.stderr.read() or "").strip() if self.proc.stderr else ""
            raise RuntimeError("tcpdump failed to start on {}: {}".format(self.interface, stderr or "unknown error"))

    def stop(self):
        subprocess.run(["sudo", "-n", "pkill", "-f", " ".join(self.get_start_cmd())], check=True)
        self.proc.wait()

    def get_start_cmd(self):
        return ["tcpdump", "-B", "8192", "-i", self.interface, "-s", "100", "-w", self.output_file]
