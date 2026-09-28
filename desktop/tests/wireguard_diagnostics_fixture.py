"""Independent wireguard-go peer relaying tunnel traffic to the owned IP/Speedtest services."""
import json
import os
from pathlib import Path
import select
import subprocess

from diagnostics_services_fixture import Fixture as ServicesFixture, HOSTS


class Fixture(ServicesFixture):
    def __init__(self, directory, peer_binary):
        assert os.getpid() == 1
        super().__init__(directory, hosts=HOSTS)
        self.peer = None
        directory = Path(directory)
        try:
            options = directory / 'peer.options.json'
            options.write_text(json.dumps({'forwardPorts': [443, self.http.server_port]}))
            options.chmod(0o600)
            self.peer_log = (directory / 'peer.stderr.log').open('w')
            self.peer = subprocess.Popen([str(peer_binary), str(directory / 'peer'), '127.0.0.1', str(options)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.peer_log, text=True)
            assert select.select([self.peer.stdout], [], [], 10)[0], 'independent WG peer readiness timeout'
            ready = json.loads(Path(self.peer.stdout.readline().strip()).read_text())
            tunnel = ready['tunnel4']
            self.info.update(wireguard=ready['profile'], peerStats=ready['stats'], tunnel=tunnel,
                             peerEndpoint=ready['endpoint'],
                             simpleUrl='http://' + tunnel + ':' + str(self.http.server_port) + '/speedtest/random1000x1000.jpg')
            self.path.write_text(json.dumps(self.info)); self.path.chmod(0o600)
        except BaseException:
            self.close()
            raise

    def close(self):
        code = None
        if self.peer:
            if not self.peer.stdin.closed: self.peer.stdin.close()
            try: code = self.peer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.peer.kill(); code = self.peer.wait(timeout=5)
            self.peer_log.close()
        result = super().close()
        result.update(peerExit=code, peerReaped=self.peer is None or self.peer.poll() is not None)
        return result
