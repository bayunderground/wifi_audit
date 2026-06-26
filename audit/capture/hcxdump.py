"""
Capture backend abstraction.
"""

class CaptureSession:
    def __init__(self,bssid:str,channel:int):
        self.bssid=bssid
        self.channel=channel

    def start(self):
        # TODO:
        # Start hcxdumptool (or another backend) here.
        pass

    def stop(self):
        # TODO:
        # Stop capture backend.
        pass

    def handshake_detected(self)->bool:
        # TODO:
        # Detect whether handshake/PMKID has been captured.
        return False
