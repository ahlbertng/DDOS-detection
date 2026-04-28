import time


class Unbanner:
    def __init__(self, state, blocker):
        self.state = state
        self.blocker = blocker

    def run(self):
        while True:
            now = time.time()
            to_unban = []

            with self.state.lock:
                for ip, info in list(self.state.banned_ips.items()):
                    expires_at = info.get("expires_at")
                    if expires_at and now >= expires_at:
                        to_unban.append(ip)

            for ip in to_unban:
                self.blocker.unban(ip)

            time.sleep(5)