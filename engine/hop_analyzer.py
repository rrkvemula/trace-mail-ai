"""
Hop timestamp consistency analyzer.
Detects reversed or unusually delayed timestamps without claiming attribution.
"""

from datetime import datetime
from typing import List, Dict, Any, Tuple

class HopAnalyzer:
    """Evaluates the integrity of the SMTP Received: relay chain."""

    # Maximum acceptable reverse clock skew before flagging as suspicious (seconds)
    CLOCK_TOLERANCE_SECONDS = 60.0

    def __init__(self, hops: List[Dict[str, Any]]):
        self.hops = hops

    def analyze(self) -> Dict[str, Any]:
        """Performs full hop-by-hop latency and integrity analysis."""
        if not self.hops or len(self.hops) < 2:
            return {
                "analyzed_hops": self.hops,
                "anomalies": [],
                "has_timing_anomalies": False,
                "total_transit_seconds": 0.0,
                "hop_reliability_index": 100.0,
                "header_consistency_score": 100.0,
                "verdict": "Single hop or internal delivery; integrity intact."
            }

        analyzed_hops = []
        anomalies = []
        has_timing_anomalies = False
        total_transit_time = 0.0

        for i in range(len(self.hops)):
            current_hop = dict(self.hops[i])
            delta_seconds = None
            anomaly_detected = False
            anomaly_reason = None

            if i > 0:
                prev_hop = analyzed_hops[i - 1]
                t_prev_iso = prev_hop.get("timestamp_iso")
                t_curr_iso = current_hop.get("timestamp_iso")

                if t_prev_iso and t_curr_iso:
                    try:
                        dt_prev = datetime.fromisoformat(t_prev_iso)
                        dt_curr = datetime.fromisoformat(t_curr_iso)
                        delta_seconds = (dt_curr - dt_prev).total_seconds()
                        total_transit_time += max(0.0, delta_seconds)

                        # Reversed timestamps may indicate manipulation, clock skew, or malformed data.
                        if delta_seconds < -self.CLOCK_TOLERANCE_SECONDS:
                            anomaly_detected = True
                            has_timing_anomalies = True
                            anomaly_reason = (
                                f"Reversed relay timestamp ({delta_seconds:.1f}s). "
                                "Possible causes include clock skew, malformed data, or header manipulation."
                            )
                            anomalies.append({
                                "hop_index": current_hop["hop_number"],
                                "severity": "HIGH",
                                "type": "REVERSED_RELAY_TIMESTAMP",
                                "details": anomaly_reason
                            })

                        # Check 2: Severe Delay (> 2 hours) indicating greylisting or queue hijacking
                        elif delta_seconds > 7200.0:
                            anomaly_detected = True
                            anomaly_reason = f"Abnormal relay delay ({delta_seconds / 3600.0:.1f} hours)."
                            anomalies.append({
                                "hop_index": current_hop["hop_number"],
                                "severity": "WARNING",
                                "type": "EXCESSIVE_RELAY_DELAY",
                                "details": anomaly_reason
                            })

                    except Exception as ex:
                        delta_seconds = None

            current_hop["delta_seconds"] = delta_seconds
            current_hop["anomaly"] = anomaly_detected
            current_hop["anomaly_reason"] = anomaly_reason
            current_hop["integrity_status"] = "TIMESTAMP_ANOMALY" if anomaly_detected else "OBSERVED"
            analyzed_hops.append(current_hop)

        # Calculate Hop Reliability Index (HRI)
        penalty = 0.0
        for a in anomalies:
            if a["severity"] == "HIGH":
                penalty += 40.0
            elif a["severity"] == "WARNING":
                penalty += 15.0
            elif a["severity"] == "MEDIUM":
                penalty += 10.0

        hri = max(5.0, min(100.0, 100.0 - penalty))

        verdict = "No timestamp inconsistencies detected in the submitted relay headers."
        if has_timing_anomalies:
            verdict = "Reversed relay timestamps require analyst review; manipulation is one possible explanation."
        elif anomalies:
            verdict = "Unusual relay delay detected and requires analyst review."

        return {
            "analyzed_hops": analyzed_hops,
            "anomalies": anomalies,
            "has_timing_anomalies": has_timing_anomalies,
            "total_transit_seconds": round(total_transit_time, 2),
            "hop_reliability_index": round(hri, 1),
            "header_consistency_score": round(hri, 1),
            "verdict": verdict
        }
