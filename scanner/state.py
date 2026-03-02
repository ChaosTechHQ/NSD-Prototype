# scanner/state.py — ChaosTech NSD shared state singleton
import threading, time

class NSDState:
    def __init__(self):
        self.lock         = threading.Lock()
        self.cache        = {
            "center_mhz":     1090.0,
            "noise_floor_db": None,
            "points":         [],
            "peaks":          [],
            "threats":        [],
            "timestamp":      None,
            "status":         "starting",
            "error":          None,
            "total_detected": 0,
            "active_band":    "UNK",
        }
        self.threat_tracker      = {}   # freq_bucket -> {id, ttl, first_seen}
        self.persistence         = {}   # freq_bucket -> consecutive scan count
        self.next_threat_id      = 1
        self.threat_states       = {}   # tid -> DETECTED|ENGAGED|NEUTRALIZED
        self.unique_threat_ids   = set()
        self.start_time          = time.time()

        # Counters
        self.threats_engaged     = 0
        self.threats_neutralized = 0
        self.autonomous_actions  = 0
        self.swarms_detected     = 0
        self.swarms_eliminated   = 0
        self.active_swarms       = set()
        self.total_threats_detected = 0

        # System config
        self.system_active       = False
        self.system_mode         = "RF_JAM"
        self.autonomous_enabled  = False
        self.auto_engage         = False
        self.threat_threshold    = 70

        # Band rotation
        self.band_index          = 0
        self.scan_center_mhz     = 1090.0
        self.scan_span_mhz       = 2.0

state = NSDState()   # singleton — import this everywhere
