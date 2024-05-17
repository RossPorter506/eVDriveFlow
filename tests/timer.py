import time

# File to measure time taken in various parts of the charging session

class Timer:
    def __init__(self):
        self.start_time: Optional[float] = None
        self.elapsed_time: Optional[float] = 0
    
    def start(self):
        self.start_time = time.perf_counter()
    
    def lap(self) -> float:
        elapsed_time = time.perf_counter() - self.start_time
        return elapsed_time + self.elapsed_time

    def stop(self) -> float:
        elapsed_time = self.lap()
        self.start_time = None
        self.elapsed_time = 0
        return elapsed_time + self.elapsed_time
    
    def pause(self):
        self.elapsed_time += time.perf_counter() - self.start_time
        self.start_time = None
    
    def resume(self):
        self.start_time = time.perf_counter()

handshake_timer = Timer()
attestation_timer = Timer()
validation_timer = Timer()
total_negotiation_timer = Timer()
