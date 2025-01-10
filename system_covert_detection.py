import logging
from scapy.all import sniff, DNS

# Initialize data structures for flag storage
flag_data = {
    "Opcode": [],
    "AA": [],
    "TC": [],
    "RD": [],
    "RA": []
}

# Define custom log levels
START_LEVEL = 25
ALERT_LEVEL = 35
ACTION_LEVEL = 45

logging.addLevelName(START_LEVEL, "START")
logging.addLevelName(ALERT_LEVEL, "ALERT")
logging.addLevelName(ACTION_LEVEL, "ACTION")

def start(self, message, *args, **kws):
    if self.isEnabledFor(START_LEVEL):
        self._log(START_LEVEL, message, args, **kws)

def alert(self, message, *args, **kws):
    if self.isEnabledFor(ALERT_LEVEL):
        self._log(ALERT_LEVEL, message, args, **kws)

def action(self, message, *args, **kws):
    if self.isEnabledFor(ACTION_LEVEL):
        self._log(ACTION_LEVEL, message, args, **kws)

logging.Logger.start = start
logging.Logger.alert = alert
logging.Logger.action = action

# Configure logging
logging.basicConfig(level=START_LEVEL, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)
def log(message):
    """Utility function for logging process steps."""
    print(f"[INFO] {message}")
def capture_network_traffic():
    """Simulate network traffic capture process."""
    logger.start("Initializing network traffic capture module...")
    # Simulated steps for capturing network traffic
    log("Capturing all network communication data streams in real-time...")
    log("Extracting data across Link, Network, Transport, and Application layers...")
    log("Network traffic capture initialized.")
    log("Parsing traffic flow...")
    log("DNS packet parsed and flags stored.")

def parse_and_store_packet(pkt):
    """Parse DNS packet flags and store them."""
    if DNS in pkt and pkt[DNS].qr == 0:  # Process only DNS query packets
        # Extract flag fields
        opcode = pkt[DNS].opcode
        aa = pkt[DNS].aa
        tc = pkt[DNS].tc
        rd = pkt[DNS].rd
        ra = pkt[DNS].ra

        # Store flag data
        flag_data["Opcode"].append(opcode)
        flag_data["AA"].append(aa)
        flag_data["TC"].append(tc)
        flag_data["RD"].append(rd)
        flag_data["RA"].append(ra)

def compute_feature_vector():
    """Compute five-dimensional feature vector."""
    log("Computing feature vector from captured data...")
    total_queries = len(flag_data["Opcode"])
    total_responses = len(flag_data["AA"])  # AA, TC, RA are response features

    if total_queries == 0 or total_responses == 0:
        logger.alert("Insufficient data for feature computation.")
        return None

    f1 = flag_data["Opcode"].count(0) / total_queries  # Opcode = 0
    f2 = flag_data["AA"].count(1) / total_responses    # AA = 1
    f3 = flag_data["TC"].count(0) / total_responses    # TC = 0 (not truncated)
    f4 = flag_data["RD"].count(1) / total_queries      # RD = 1
    f5 = flag_data["RA"].count(1) / total_responses    # RA = 1

    feature_vector = [f1, f2, f3, f4, f5]
    log(f"Feature vector computed: {feature_vector}")
    return feature_vector

def detect_anomalies():
    """Detect anomalies based on weighted absolute difference."""
    features = compute_feature_vector()
    if features is None:
        logger.alert("Anomaly detection aborted due to insufficient data.")
        return

    # Define weighting coefficients
    weights = [1, 1.5, 2, 1, 1.2]  # Set weighting coefficients

    # Compute weighted absolute difference sum
    ideal_values = [0.99, 0.9, 0.01, 0.95, 0.9]
    anomaly_score = sum(weights[i] * abs(features[i] - ideal_values[i])
                        for i in range(len(features)))

    # Define threshold
    threshold = 2.5  # Adjust threshold as needed

    # Determine if anomaly exists
    if anomaly_score > threshold:
        logger.alert(f"Anomalous DNS communication detected with score: {anomaly_score}")
        intercept_anomalous_traffic()
    else:
        log(f"No anomalies detected. Anomaly score: {anomaly_score}")

def intercept_anomalous_traffic():
    """Simulate interception of anomalous traffic."""
    logger.action("Initiating interception of anomalous traffic...")
    # Simulated steps for traffic interception
    logger.action("Identifying network flows associated with anomalies...")
    logger.action("Blocking identified anomalous traffic at network layer...")
    log("Logging details of intercepted anomalous traffic...")
    log("Anomalous traffic interception completed.")

def capture_dns_traffic(timeout=30):
    """Capture DNS traffic and process packets."""
    capture_network_traffic()
    sniff(filter="udp port 53", prn=parse_and_store_packet, timeout=timeout)
    detect_anomalies()

if __name__ == "__main__":
    capture_dns_traffic()
