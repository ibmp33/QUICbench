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
        if not hasattr(self, "proc") or self.proc.poll() is not None:
            return self.proc.returncode if hasattr(self, "proc") else None
        # Stop exactly the capture process started by this object. A pattern-wide
        # pkill can terminate captures belonging to another run or user.
        self.proc.terminate()
        try:
            return self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait(timeout=5)

    def get_start_cmd(self):
        return ["tcpdump", "-B", "8192", "-i", self.interface, "-s", "100", "-w", self.output_file]
