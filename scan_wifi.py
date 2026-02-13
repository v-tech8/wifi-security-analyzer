import subprocess
import re
import random

def get_wifi_info():
    """
    Scans for current Wi-Fi connection details using system_profiler.
    Returns a dictionary with:
    - ssid (str)
    - bssid (str)
    - signal_strength (int)
    - channel (int)
    - encryption (int: 0=Open, 1=WPA2, 2=WPA3)
    - packet_anomaly (int: 0 or 1 - simulated)
    - ssid_similarity (int: 0-100 - simulated)
    """
    wifi_data = {
        "ssid": "Unknown",
        "bssid": "00:00:00:00:00:00",
        "signal_strength": -100,
        "channel": 1,
        "encryption": 0,
        "packet_anomaly": 0,
        "ssid_similarity": 0
    }

    try:
        # Use system_profiler to get Wi-Fi info
        cmd = ["system_profiler", "SPAirPortDataType"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout

        if result.returncode == 0 and output:
            # Split into sections by interface (en0, awdl0, etc.)
            sections = re.split(r'\n\s{8}(\w+):\n', output)
            
            # Look for en0 section (main Wi-Fi interface)
            for i in range(1, len(sections), 2):
                interface_name = sections[i]
                interface_data = sections[i + 1] if i + 1 < len(sections) else ""
                
                # Skip awdl0 and other non-WiFi interfaces
                if interface_name != "en0":
                    continue
                
                # Now parse the en0 section
                lines = interface_data.split('\n')
                in_current_network = False
                current_ssid = None
                
                for line in lines:
                    if "Current Network Information:" in line:
                        in_current_network = True
                        continue
                    
                    if in_current_network:
                        # The SSID is the first indented line after "Current Network Information:"
                        # It looks like: "            SSID_NAME:"
                        if current_ssid is None:
                            stripped = line.strip()
                            if stripped and stripped.endswith(':') and not any(key in stripped for key in 
                                ['PHY Mode', 'BSSID', 'Channel', 'Country', 'Network Type', 'Security', 'Signal', 'Transmit', 'MCS', 'MAC Address']):
                                current_ssid = stripped.rstrip(':')
                                wifi_data["ssid"] = current_ssid
                        
                        # Extract other fields
                        if "BSSID:" in line:
                            wifi_data["bssid"] = line.split("BSSID:")[1].strip()
                        elif "Channel:" in line:
                            channel_match = re.search(r'Channel:\s*(\d+)', line)
                            if channel_match:
                                wifi_data["channel"] = int(channel_match.group(1))
                        elif "Signal / Noise:" in line:
                            signal_match = re.search(r'Signal / Noise:\s*(-?\d+)\s*dBm', line)
                            if signal_match:
                                wifi_data["signal_strength"] = int(signal_match.group(1))
                        elif "Security:" in line:
                            security = line.split("Security:")[1].strip().lower()
                            if "wpa3" in security:
                                wifi_data["encryption"] = 2
                            elif "wpa2" in security or "wpa" in security:
                                wifi_data["encryption"] = 1
                            else:
                                wifi_data["encryption"] = 0
                        
                        # Stop when we hit "Other Local Wi-Fi Networks"
                        if "Other Local Wi-Fi Networks:" in line:
                            break
                
                # If we found data in en0, we're done
                if wifi_data["ssid"] != "Unknown":
                    break
            
            # If we still didn't find a valid SSID, return mock data
            if wifi_data["ssid"] == "Unknown":
                print("Could not find connected Wi-Fi network. Using mock data.")
                return get_mock_data()
        else:
            print("system_profiler command failed. Using mock data.")
            return get_mock_data()

    except Exception as e:
        print(f"Error scanning Wi-Fi: {e}")
        import traceback
        traceback.print_exc()
        return get_mock_data()

    # Simulate missing features for risk model
    wifi_data["packet_anomaly"] = random.choice([0, 1])
    wifi_data["ssid_similarity"] = random.randint(0, 100)
    
    return wifi_data

def get_mock_data():
    """Returns mock data for testing/demo purposes."""
    return {
        "ssid": "Demo_WiFi_Network",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "signal_strength": random.randint(-80, -40),
        "channel": random.randint(1, 11),
        "encryption": random.choice([0, 1, 2]),
        "packet_anomaly": random.choice([0, 1]),
        "ssid_similarity": random.randint(0, 100)
    }

if __name__ == "__main__":
    print(get_wifi_info())
