import sys
class IAM:
    def __init__(self):
        self.enabled = False
        self.use_boottime_attestation = False
        self.use_precharge_runtime_attestation = False
        self.use_intracharge_runtime_attestation = False
        self.use_intracharge_pushnotify_runtime_attestation = False

    def configure(self, config: int):
        self.enabled = True
        
        print("################ IAM Enabled ################")
        # Selected operations bitpacked in config num
        self.use_boottime_attestation =                        bool(config & (1 << 0))
        self.use_precharge_runtime_attestation =               bool(config & (1 << 1))
        self.use_intracharge_runtime_attestation =             bool(config & (1 << 2))
        self.use_intracharge_pushnotify_runtime_attestation =  bool(config & (1 << 3))
