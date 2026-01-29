import queue

from udsoncan.connections import BaseConnection
from udsoncan.exceptions import TimeoutException


class FakeConnection(BaseConnection):
    def __init__(self, name=None, debug=False, testdata=None, *args, **kwargs):
        BaseConnection.__init__(self, name)

        self.rxqueue = queue.Queue()

        self.exit_requested = False
        self.opened = False

        self.ResponseData = testdata

    def open(self):
        self.opened = True
        self.logger.info("Fake Connection opened")
        return self

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def is_open(self):
        return self.opened

    def close(self):
        self.exit_requested = True
        self.opened = False
        self.logger.info("Fake Connection closed")

    def specific_send(self, payload):
        self.logger.debug("Received payload: " + str(payload.hex()))
        try:
            response = self.ResponseData[payload]
        except Exception:
            # Unknown payload: return a safe default so higher-level code can continue
            # Many callers expect a response starting with 0x7E/0x7e for success; use b'\x7e\x00'
            self.logger.warning(
                "FakeConnection: no canned response for payload, returning default 7E00"
            )
            response = b"\x7e\x00"

        self.rxqueue.put(response)

    def specific_wait_frame(self, timeout=4):
        if not self.opened:
            raise RuntimeError("Fake Connection is not open")

        timedout = False
        frame = None
        try:
            frame = self.rxqueue.get(block=True, timeout=timeout)
            # frame = self.rxqueue.get(block=True, timeout=5)

        except queue.Empty:
            timedout = True

        if timedout:
            raise TimeoutException(
                "Did not received response from J2534 RxQueue (timeout=%s sec)"
                % timeout
            )

        return frame

    def empty_rxqueue(self):
        while not self.rxqueue.empty():
            self.rxqueue.get()
