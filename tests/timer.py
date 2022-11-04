import time

# File to measure time taken in various parts of the charging session

class Timer:
    def __init__(self):
        self.start_time: Optional[float] = None
    
    def start(self):
        self.start_time = time.perf_counter()
    
    def lap(self) -> float:
        elapsed_time = time.perf_counter() - self.start_time
        return elapsed_time

    def stop(self) -> float:
        elapsed_time = self.lap()
        self.start_time = None
        return elapsed_time

handshake_timer = Timer()
attestation_timer = Timer()
