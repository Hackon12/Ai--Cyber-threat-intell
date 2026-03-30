import httpx
import asyncio
import threading
import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging
import json
from urllib.parse import unquote, urlparse
import ipaddress
import random
from typing import List

# Optional live packet capture support (scapy). If scapy isn't available
# we'll continue to use the simulated traffic generator. To enable live
# capture set ENABLE_LIVE_CAPTURE=true in your .env and run the app with
# appropriate privileges (administrator) and a packet capture driver
# installed (Npcap on Windows).
try:
    import scapy.all as scapy  # type: ignore
    HAVE_SCAPY = True
except Exception:
    scapy = None
    HAVE_SCAPY = False

# Capture loop handle (asyncio loop) used to schedule broadcasts from
# the scapy thread into the asyncio event loop.
_capture_event_loop = None
_simulator_task = None
_scapy_thread_started = False
# When True, scapy packet handler will broadcast; toggle via admin endpoint
_live_capture_active = False

import base64

class NetworkGraph:
    def __init__(self):
        self.nodes = []
        self.links = []

    def add_traffic(self, src_ip, dst_port):
        """Adds a representation of traffic to the graph."""
        # Ensure nodes for source and destination exist
        if not any(n['id'] == src_ip for n in self.nodes):
            self.nodes.append({"id": src_ip, "type": "ip"})
        
        dest_id = f"server_port_{dst_port}"
        if not any(n['id'] == dest_id for n in self.nodes):
            self.nodes.append({"id": dest_id, "type": "port"})
        
        # Add a link
        self.links.append({"source": src_ip, "target": dest_id, "weight": 1})

    def get_traffic_for_ip(self, ip_address):
        """Retrieves traffic information related to a specific IP."""
        related_links = [
            link for link in self.links 
            if (isinstance(link['source'], str) and link['source'] == ip_address) or \
               (isinstance(link['source'], dict) and link['source'].get('id') == ip_address)
        ]
        return related_links

    def to_dict(self):
        """Returns a dictionary representation of the graph."""
        return {"nodes": self.nodes, "links": self.links}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.network_graph = NetworkGraph()
        self.active_threats = []
        self.packet_history = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        # Safe-remove: only remove if present
        try:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        except ValueError:
            pass

    async def broadcast(self, data):
        """Broadcasts data to all connected WebSocket clients."""
        message = json.dumps(data, default=str)
        # Iterate over a shallow copy to avoid mutation during iteration
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                # Best-effort remove broken connections
                try:
                    if connection in self.active_connections:
                        self.active_connections.remove(connection)
                except Exception:
                    pass

    def get_active_threats(self):
        return self.active_threats

    def add_threat(self, threat):
        self.active_threats.append(threat)
        # Keep the list from growing indefinitely
        if len(self.active_threats) > 50:
            self.active_threats.pop(0)

    def add_packet_to_history(self, packet):
        self.packet_history.append(packet)
        if len(self.packet_history) > 100: # Store last 100 packets
            self.packet_history.pop(0)

    def get_packet_history(self):
        return self.packet_history


app = FastAPI()

# Add CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("uvicorn")
manager = ConnectionManager()

# Broadcast queue and throttling configuration to avoid overloading the frontend.
# Configure via environment variable BROADCAST_RATE (messages per second). Default: 5 msgs/sec.
_BROADCAST_QUEUE = None
_BROADCAST_RATE = float(os.environ.get('BROADCAST_RATE', '5'))
_BROADCAST_INTERVAL = 1.0 / _BROADCAST_RATE if _BROADCAST_RATE and _BROADCAST_RATE > 0 else 0.2
_broadcaster_task = None
# Max queue size to prevent unbounded memory growth. If the queue is full, oldest messages are dropped.
_MAX_BROADCAST_QUEUE_SIZE = int(os.environ.get('MAX_BROADCAST_QUEUE_SIZE', '500'))

async def enqueue_broadcast(message):
    """Safely enqueue a message for throttled broadcasting.
    If the queue is not initialized, fall back to immediate broadcast.
    If the queue is full, drop the oldest message to make room.
    """
    global _BROADCAST_QUEUE
    if _BROADCAST_QUEUE is None:
        # Fallback direct broadcast
        try:
            await manager.broadcast(message)
        except Exception:
            pass
        return

    try:
        # If queue is too large, remove one oldest item to make room
        if _BROADCAST_QUEUE.qsize() >= _MAX_BROADCAST_QUEUE_SIZE:
            try:
                _ = _BROADCAST_QUEUE.get_nowait()
            except Exception:
                # ignore if cannot pop
                pass
        await _BROADCAST_QUEUE.put(message)
    except Exception:
        # If enqueue fails, fallback to direct broadcast
        try:
            await manager.broadcast(message)
        except Exception:
            pass

# --- Global State ---
threat_intel_iocs = {"ipv4-addr": set()}
# Read API keys from environment variables. Leave empty if not configured.
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# --- Background Tasks ---

async def update_threat_intel_from_stix(run_continuously: bool = True):
    """Fetches STIX-formatted threat intelligence and updates the IOC cache."""
    global threat_intel_iocs
    if not OTX_API_KEY or OTX_API_KEY == "YOUR_OTX_API_KEY_HERE":
        logger.warning("AlienVault OTX API key is not configured. Skipping threat intelligence update.")
        return

    stix_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        logger.info("Fetching threat intelligence from AlienVault OTX...")
        async with httpx.AsyncClient() as client:
            response = await client.get(stix_url, headers=headers, timeout=30, follow_redirects=True)
            response.raise_for_status()
            stix_bundle = response.json()
        
        new_iocs = {
            "ipv4-addr": set(),
            "domain": set(),
            "hostname": set(),
            "URL": set(),
        }
        for pulse in stix_bundle.get("results", []):
            for indicator in pulse.get("indicators", []):
                ioc_type = indicator.get("type")
                ioc_value = indicator.get("indicator")
                # Map OTX types to our internal keys
                if ioc_type == "IPv4" and ioc_value: new_iocs["ipv4-addr"].add(ioc_value)
                elif ioc_type == "domain" and ioc_value: new_iocs["domain"].add(ioc_value)
                elif ioc_type == "hostname" and ioc_value: new_iocs["hostname"].add(ioc_value)
                elif ioc_type == "URL" and ioc_value: new_iocs["URL"].add(ioc_value)

        # Check if any IOCs were found, not just IPs
        if any(new_iocs.values()):
            threat_intel_iocs.update(new_iocs)
            logger.info(f"Threat intelligence updated. Loaded {len(threat_intel_iocs['ipv4-addr'])} IPv4 IOCs.")
        else:
            logger.warning("Threat intelligence feed was empty or contained no IPv4 indicators.")

    except Exception as e:
        logger.error(f"Failed to download or parse threat intelligence feed. Error: {e}")

    if run_continuously:
        await asyncio.sleep(3600)  # Update every hour
        asyncio.create_task(update_threat_intel_from_stix())

async def detect_threats():
    """Continuously monitors for threats and broadcasts them."""
    logger.info("Starting threat detection module...")
    while True:
        try:
            current_graph = manager.network_graph.to_dict()
            detected_threats = []
            for node in current_graph["nodes"]:
                if node["type"] == "ip" and node["id"] in threat_intel_iocs.get("ipv4-addr", set()):
                    detected_threats.append({
                        "type": "malicious_ip_source",
                        "ip": node["id"],
                        "timestamp": datetime.now().isoformat()
                    })
            if detected_threats:
                for threat in detected_threats:
                    manager.add_threat(threat)

                logger.warning(f"Detected {len(detected_threats)} threats: {detected_threats}")
                # Enqueue threat broadcasts to the throttled broadcaster
                try:
                    if _BROADCAST_QUEUE is not None:
                        await enqueue_broadcast({"threats": detected_threats})
                    else:
                        await manager.broadcast({"threats": detected_threats})
                except Exception:
                    # best-effort: fall back to direct broadcast
                    await manager.broadcast({"threats": detected_threats})
            await asyncio.sleep(5)  # Check for threats every 5 seconds
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            await asyncio.sleep(10)  # Wait longer if an error occurs

# --- Startup Events ---

@app.on_event("startup")
async def on_startup():
    """Initializes background tasks when the application starts."""
    asyncio.create_task(update_threat_intel_from_stix())

    # Decide whether to use live packet capture or simulated data. Use
    # the environment variable ENABLE_LIVE_CAPTURE to allow opting in
    # without changing code. Live capture requires scapy and OS
    # permissions (run as admin on Windows) and a capture driver like
    # Npcap.
    enable_live = os.environ.get('ENABLE_LIVE_CAPTURE', 'false').lower() in ('1', 'true', 'yes')
    global _simulator_task, _scapy_thread_started, _live_capture_active, _capture_event_loop
    _live_capture_active = enable_live and HAVE_SCAPY
    if _live_capture_active:
        _capture_event_loop = asyncio.get_running_loop()
        logger.info('Starting live packet capture (scapy) ...')
        start_scapy_sniffer()
        _scapy_thread_started = True
    else:
        if enable_live and not HAVE_SCAPY:
            logger.warning('ENABLE_LIVE_CAPTURE set but scapy is not available. Falling back to simulated traffic.')
        # Start the simulator task and keep a reference so we can cancel it later
        if _simulator_task is None or _simulator_task.done():
            _simulator_task = asyncio.create_task(simulate_live_data())

    # Initialize broadcast queue and broadcaster task to throttle websocket messages
    global _BROADCAST_QUEUE, _broadcaster_task, _BROADCAST_INTERVAL
    if _BROADCAST_QUEUE is None:
        _BROADCAST_QUEUE = asyncio.Queue()

    async def _broadcaster():
        logger.info(f"Starting broadcaster task with interval={_BROADCAST_INTERVAL}s")
        while True:
            try:
                msg = await _BROADCAST_QUEUE.get()
                if msg is None:
                    continue
                try:
                    await manager.broadcast(msg)
                except Exception as e:
                    logger.error(f"Error broadcasting message: {e}")
                # Sleep to throttle outgoing messages
                if _BROADCAST_INTERVAL and _BROADCAST_INTERVAL > 0:
                    await asyncio.sleep(_BROADCAST_INTERVAL)
            except Exception as e:
                logger.error(f"Broadcaster loop error: {e}")

    if _broadcaster_task is None or _broadcaster_task.done():
        _broadcaster_task = asyncio.create_task(_broadcaster())


async def simulate_live_data():
    """Simulates live traffic, threats, and graph updates."""
    logger.info("Starting live data simulation...")
    internal_ips = [f"192.168.1.{i}" for i in range(100, 105)]
    while True:
        await asyncio.sleep(random.uniform(0.5, 3))

        # Simulate a traffic packet
        src_ip = random.choice(internal_ips)
        dst_port = random.choice([80, 443, 8080, 22, 3389])
        severity = "normal"
        if src_ip in threat_intel_iocs.get("ipv4-addr", set()):
            severity = "high"
            # Create and add a threat event for the chart
            # This threat is now more detailed for the ActiveThreats component
            threat = {
                "type": "Malicious IP Traffic",
                "target": src_ip,
                "timestamp": datetime.now().isoformat(),
                "count": 1 # Add count for consistency
            }
            manager.add_threat(threat)
            # Enqueue threat broadcast
            if _BROADCAST_QUEUE is not None:
                await enqueue_broadcast({"threats": [threat]})
            else:
                await manager.broadcast({"threats": [threat]})
        elif random.random() < 0.1:
            severity = "medium"

        packet = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": severity,
        }
        manager.add_packet_to_history(packet)
        # Enqueue packet broadcast (throttled)
        if _BROADCAST_QUEUE is not None:
            await enqueue_broadcast({"packet": packet})
        else:
            await manager.broadcast({"packet": packet})

        # Add traffic to graph and broadcast update
        manager.network_graph.add_traffic(src_ip, dst_port)
        if _BROADCAST_QUEUE is not None:
            await enqueue_broadcast({"graph": manager.network_graph.to_dict()})
        else:
            await manager.broadcast({"graph": manager.network_graph.to_dict()})


def _scapy_packet_handler(pkt):
    """Callback run in scapy thread for each captured packet."""
    try:
        # Extract IP layer information
        src_ip = None
        dst_port = None
        protocol = 'OTHER'

        if pkt.haslayer('IP'):
            ip_layer = pkt['IP']
            src_ip = ip_layer.src
            protocol = ip_layer.proto
        elif pkt.haslayer('IPv6'):
            ip_layer = pkt['IPv6']
            src_ip = ip_layer.src
            protocol = 'IPv6'

        # TCP/UDP destination port if present
        if pkt.haslayer('TCP'):
            dst_port = int(pkt['TCP'].dport)
            protocol = 'TCP'
        elif pkt.haslayer('UDP'):
            dst_port = int(pkt['UDP'].dport)
            protocol = 'UDP'

        if not src_ip:
            return

        severity = 'normal'
        if src_ip in threat_intel_iocs.get('ipv4-addr', set()):
            severity = 'high'

        packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_port': dst_port or 0,
            'protocol': protocol,
            'severity': severity,
        }

        # Schedule into asyncio loop
        try:
            if _capture_event_loop:
                asyncio.run_coroutine_threadsafe(_handle_captured_packet(packet), _capture_event_loop)
        except Exception:
            pass
    except Exception:
        # Swallow exceptions in packet handler to avoid crashing capture thread
        return


async def _handle_captured_packet(packet):
    """Async helper scheduled in main loop to process and broadcast captured packet."""
    try:
        manager.add_packet_to_history(packet)
        manager.network_graph.add_traffic(packet.get('src_ip', 'unknown'), packet.get('dst_port', 0))
        # Enqueue captured packet and graph update to the throttled broadcaster
        if _BROADCAST_QUEUE is not None:
            await _BROADCAST_QUEUE.put({'packet': packet})
            await _BROADCAST_QUEUE.put({'graph': manager.network_graph.to_dict()})
        else:
            await manager.broadcast({'packet': packet})
            await manager.broadcast({'graph': manager.network_graph.to_dict()})
    except Exception as e:
        logger.error(f"Error processing captured packet: {e}")


@app.get("/admin/capture")
async def admin_get_capture_status():
    """Returns current capture mode and scapy availability."""
    return {
        "mode": "live" if _live_capture_active else "sim",
        "have_scapy": HAVE_SCAPY,
        "scapy_thread_started": _scapy_thread_started,
    }


@app.post("/admin/capture")
async def admin_set_capture(payload: dict):
    """Set capture mode. Payload: {"mode": "live"|"sim"}.

    Switching to 'live' will start scapy sniffer if available. Switching
    to 'sim' will enable the simulator task. This endpoint is intended
    for local admin/testing only.
    """
    mode = (payload or {}).get('mode', '').lower()
    if mode not in ('live', 'sim'):
        raise HTTPException(status_code=400, detail="mode must be 'live' or 'sim'")

    global _simulator_task, _scapy_thread_started, _live_capture_active, _capture_event_loop

    if mode == 'live':
        if not HAVE_SCAPY:
            raise HTTPException(status_code=400, detail='Scapy not available on this server')
        _live_capture_active = True
        if not _scapy_thread_started:
            _capture_event_loop = asyncio.get_running_loop()
            start_scapy_sniffer()
            _scapy_thread_started = True
        # If simulator is running, cancel it
        if _simulator_task and not _simulator_task.done():
            _simulator_task.cancel()
            _simulator_task = None
        return {"mode": "live", "message": "Live capture enabled"}

    # mode == 'sim'
    _live_capture_active = False
    # Start simulator if not running
    if _simulator_task is None or _simulator_task.done():
        _simulator_task = asyncio.create_task(simulate_live_data())
    return {"mode": "sim", "message": "Simulator enabled"}


def start_scapy_sniffer():
    """Start scapy sniffing in a background thread."""
    if not HAVE_SCAPY:
        logger.warning('Scapy not installed; live packet capture is disabled.')
        return

    def _sniff():
        try:
            # sniff indefinitely; prn will be called for each packet
            scapy.sniff(prn=_scapy_packet_handler, store=False)
        except Exception as e:
            logger.error(f"Scapy sniff failed: {e}")

    t = threading.Thread(target=_sniff, daemon=True)
    t.start()


# --- API Endpoints ---

@app.get("/api/dashboard-data")
async def get_dashboard_data():
    """Returns a consolidated report of all major dashboard data points."""
    # Convert sets to lists for JSON serialization
    iocs = {
        "ipv4-addr": list(threat_intel_iocs.get("ipv4-addr", [])),
        "domain": list(threat_intel_iocs.get("domain", [])),
        "hostname": list(threat_intel_iocs.get("hostname", [])),
        "URL": list(threat_intel_iocs.get("URL", []))}
    
    return {
        "graph": manager.network_graph.to_dict(),
        "packets": manager.get_packet_history(),
        "active_threats": manager.get_active_threats(),
        "iocs": iocs,
        "predictions": await get_predictions() # Re-use existing mock function
    }

@app.get("/api/threat_intel")
async def get_threat_intel():
    """Returns the current threat intelligence IOCs."""
    # Convert sets to lists for JSON serialization
    return {
        "ipv4-addr": list(threat_intel_iocs.get("ipv4-addr", [])),
        "domain": list(threat_intel_iocs.get("domain", [])),
        "hostname": list(threat_intel_iocs.get("hostname", [])),
        "URL": list(threat_intel_iocs.get("URL", []))}

@app.get("/api/graph")
async def get_graph_data():
    """Returns the current network graph data."""
    return manager.network_graph.to_dict()


@app.get("/api/network-graph")
async def get_network_graph_alias():
    """Compatibility alias for older frontend code that requested /api/network-graph.
    Returns the same payload as /api/graph.
    """
    return manager.network_graph.to_dict()

@app.post("/api/scan/url")
async def scan_url(payload: dict):
    """Placeholder for scanning a URL."""
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required.")

    logger.info(f"Scanning URL: {url}")
    # In a real scenario, this would use a service like VirusTotal

    # If VirusTotal API key not configured, return a graceful response so frontend can show helpful message
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured. Returning graceful response.")
        return {
            "malicious": False,
            "details": "VirusTotal API key not configured on the server. Configure VIRUSTOTAL_API_KEY to enable URL scanning.",
            "available": False
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        async with httpx.AsyncClient() as client:
            # VirusTotal requires URL to be base64 encoded for direct lookup
            # The base64 encoding should be URL-safe and without padding
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # Step 1: Check if URL has been analyzed before
            check_url_endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
            response = await client.get(check_url_endpoint, headers=headers, timeout=30)

            malicious_count = 0
            total_scanners = 0

            if response.status_code == 200:
                # URL was found, the response contains the latest analysis report
                url_report = response.json()
                stats = url_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)

            elif response.status_code == 404:
                # URL not found in VirusTotal's database, submit for analysis
                submit_url_endpoint = "https://www.virustotal.com/api/v3/urls"
                submit_response = await client.post(submit_url_endpoint, headers=headers, data={"url": url}, timeout=30)
                submit_response.raise_for_status() # Raise for HTTP errors (e.g., 401, 429)

                analysis_id = submit_response.json()["data"]["id"]
                report_url_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                
                # Poll the analysis endpoint until it's completed
                for _ in range(10): # Poll up to 10 times (e.g., 50 seconds total)
                    logger.info(f"Polling analysis report for ID: {analysis_id}")
                    await asyncio.sleep(5) # Wait before polling
                    report_response = await client.get(report_url_endpoint, headers=headers, timeout=30)
                    report_response.raise_for_status()
                    analysis_report = report_response.json()
                    
                    if analysis_report.get("data", {}).get("attributes", {}).get("status") == "completed":
                        stats = analysis_report.get("data", {}).get("attributes", {}).get("stats", {})
                        malicious_count = stats.get("malicious", 0)
                        break # Exit loop once report is complete
                else: # This 'else' belongs to the 'for' loop
                    raise HTTPException(status_code=408, detail="URL analysis timed out. Please try again later.")

            else:
                response.raise_for_status() # Raise for other HTTP errors (e.g., 401, 429)

            # Parse the VirusTotal report to determine maliciousness
            # This block is now correctly reached for both existing and new reports
            stats = locals().get('stats', {}) # Use stats if defined, otherwise empty dict
            if stats:
                total_scanners = sum(stats.values())

            is_malicious = malicious_count > 0
            details = f"Detected by {malicious_count}/{total_scanners} security vendors. "
            if is_malicious:
                details += "This URL is potentially malicious. Review the full report on VirusTotal for more details."
            else:
                details += "No malicious detections found. This URL appears to be safe based on the scan."

            return {"url": url, "malicious": is_malicious, "details": details, "available": True}

    except httpx.HTTPStatusError as e:
        logger.error(f"Error from VirusTotal API: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to scan URL with VirusTotal: {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during URL scan: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred during URL scan.")

@app.get("/api/geolocate")
async def geolocate_ip(ip: str):
    """Placeholder for IP geolocation."""
    return {"ip": ip, "city": "Mock City", "country": "Mock Country"}

@app.get("/api/ip-report/{ip_address:path}")
async def get_ip_report(ip_address: str):
    """Checks if an IP is in the threat intel list and returns a report.

    The path converter is used so that callers may pass a URL-encoded
    value (for example when the frontend mistakenly passes a full URL).
    We sanitize and extract a host/IP portion and validate it. If the
    provided value isn't a valid IP address we return a 422 with a
    helpful message and a localTraffic section so the UI can still show
    local data.
    """
    # Decode any percent-encoding and try to extract a hostname/IP
    raw = unquote(ip_address or "")
    host = raw
    try:
        if "//" in raw:
            parsed = urlparse(raw)
            # urlparse places host in hostname (without port) or netloc
            host = parsed.hostname or parsed.netloc or raw

        # If host still contains a port, remove it (e.g. 127.0.0.1:8000)
        if host and ":" in host:
            # For IPv6 this will need more care; attempt simple split for common cases
            if host.count(":") == 1:
                host = host.split(":")[0]

        # Validate that the host is an IP address
        try:
            ip_obj = ipaddress.ip_address(host)
            ip_for_query = str(ip_obj)
        except Exception:
            # Not a valid IP address; return local data and an explanatory note
            logger.warning(f"Invalid IP for ip-report: {ip_address} -> {host}")
            local_traffic = manager.network_graph.get_traffic_for_ip(host)
            return JSONResponse(status_code=422, content={
                "localTraffic": local_traffic,
                "externalReport": None,
                "available": False,
                "note": "Provided value is not a valid IPv4/IPv6 address. Provide a canonical IP address for external reputation queries."
            })
    except Exception as e:
        logger.error(f"Error parsing ip-address parameter: {e}")
        raise HTTPException(status_code=400, detail="Invalid ip_address parameter.")
    # If AbuseIPDB API key is not configured, return a graceful partial report
    if not ABUSEIPDB_API_KEY:
        logger.warning("AbuseIPDB API key not configured. Returning partial local report.")
        # Use sanitized ip_for_query for local lookups so results match external query
        local_traffic = manager.network_graph.get_traffic_for_ip(ip_for_query)
        return {
            "localTraffic": local_traffic,
            "externalReport": None,
            "available": False,
            "note": "AbuseIPDB API key not configured on server. External reputation unavailable."
        }

    logger.info(f"Fetching AbuseIPDB report for: {ip_for_query}")
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    querystring = {
        'ipAddress': ip_for_query,
        'maxAgeInDays': '90'
    }

    # Get local traffic data from our network graph (use sanitized ip_for_query)
    local_traffic = manager.network_graph.get_traffic_for_ip(ip_for_query)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
            response.raise_for_status()
            # The API nests the data, so we return the nested object
            external_report_data = response.json().get("data", {})
            
            # Combine local and external data into a single report
            report = {
                "localTraffic": local_traffic,
                "externalReport": external_report_data
            }
            return report
    except httpx.HTTPStatusError as e:
        logger.error(f"Error fetching AbuseIPDB report: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to fetch report from AbuseIPDB.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")

@app.get("/api/active-threats")
async def get_active_threats():
    """Returns a list of currently detected active threats."""
    return manager.get_active_threats()

@app.get("/api/predictions")
async def get_predictions():
    """Returns mock prediction data."""
    # The frontend expects an array of prediction objects.
    return [
        {"prediction": "No anomalies forecasted.", "confidence": 100},
        {"prediction": "Potential port scan from 192.168.1.102", "confidence": 45},
        {"prediction": "Unusual traffic to port 3389", "confidence": 60},
    ]

@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...)):
    """Accepts a file upload and returns a placeholder scan result.

    In a production deployment this would send the file to a scanning API
    such as VirusTotal or another file analysis service.
    """
    filename = file.filename
    try:
        # Note: we intentionally do not store the file on disk in this prototype.
        contents = await file.read()
        size = len(contents)
    except Exception:
        size = None

    # If VirusTotal key is not configured, return a friendly placeholder result.
    if not VIRUSTOTAL_API_KEY:
        return {
            "filename": filename,
            "is_malicious": False,
            "reason": "VirusTotal API key not configured on server; scanning disabled.",
            "size": size,
            "available": False
        }

    # In real use we'd upload 'contents' to the scanning API. For now return a safe placeholder.
    return {
        "filename": filename,
        "is_malicious": False,
        "reason": "No threats detected (scan simulated).",
        "size": size,
        "available": True
    }

@app.get("/api/threats")
async def get_threats():
    """Returns a list of currently detected threats."""
    return manager.get_active_threats()

@app.get("/api/graph/clear")
async def clear_graph():
    """Clears the current network graph."""
    manager.network_graph = NetworkGraph()
    if _BROADCAST_QUEUE is not None:
        await _BROADCAST_QUEUE.put({"graph": manager.network_graph.to_dict()})
    else:
        await manager.broadcast({"graph": manager.network_graph.to_dict()})
    return {"message": "Network graph cleared."}

@app.post("/api/simulate_attack")
async def simulate_attack(ip_address: str):
    """Simulates an attack from a given IP address."""
    logger.info(f"Simulating attack from IP: {ip_address}")
    manager.network_graph.add_traffic(ip_address, 80)

    threat_intel_iocs["ipv4-addr"].add(ip_address)

    if ip_address in threat_intel_iocs.get("ipv4-addr", set()):
        detected_threat = {
            "type": "simulated_malicious_ip_source",
            "ip": ip_address,
            "timestamp": datetime.now().isoformat()
        }
        logger.warning(f"Simulated attack detected from known malicious IP: {ip_address}")
        # Record the threat in the manager so API clients (and initial HTTP fetches)
        # see the newly-detected threat immediately.
        try:
            manager.add_threat(detected_threat)
        except Exception:
            logger.exception("Failed to add simulated threat to manager")
        if _BROADCAST_QUEUE is not None:
            await _BROADCAST_QUEUE.put({"threats": [detected_threat]})
        else:
            await manager.broadcast({"threats": [detected_threat]})
        return {"message": f"Simulated attack from {ip_address} detected and broadcast.", "threat_detected": True}
    else:
        if _BROADCAST_QUEUE is not None:
            await _BROADCAST_QUEUE.put({"graph": manager.network_graph.to_dict()})
        else:
            await manager.broadcast({"graph": manager.network_graph.to_dict()})
        return {"message": f"Simulated attack from {ip_address} added to graph.", "threat_detected": False}

# --- WebSocket Endpoint ---

@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection open
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected from WebSocket.")


@app.get("/health")
async def health_check():
    """Simple health check endpoint for monitoring."""
    return JSONResponse({"status": "ok"})


@app.post("/admin/emit")
async def admin_emit(payload: dict):
    """Admin helper to emit test packets or threat events over the websocket. Useful for debugging.

    Payload examples:
    - {"packet": {"timestamp":..., "src_ip":"1.2.3.4", "dst_port":80, ...}}
    - {"threat": {"type":"test","ip":"1.2.3.4","timestamp":...}}
    - {} (empty) -> emits a generated test packet
    """
    try:
        if payload is None:
            payload = {}

        if 'packet' in payload:
            pkt = payload['packet']
            manager.add_packet_to_history(pkt)
            # Enqueue broadcasts
            if _BROADCAST_QUEUE is not None:
                await _BROADCAST_QUEUE.put({"packet": pkt})
            else:
                await manager.broadcast({"packet": pkt})
            # update graph as well
            try:
                manager.network_graph.add_traffic(pkt.get('src_ip', 'unknown'), pkt.get('dst_port', 0))
                if _BROADCAST_QUEUE is not None:
                    await _BROADCAST_QUEUE.put({"graph": manager.network_graph.to_dict()})
                else:
                    await manager.broadcast({"graph": manager.network_graph.to_dict()})
            except Exception:
                pass
            return JSONResponse({"sent": True, "type": "packet"})

        if 'threat' in payload:
            threat = payload['threat']
            manager.add_threat(threat)
            if _BROADCAST_QUEUE is not None:
                await _BROADCAST_QUEUE.put({"threats": [threat]})
            else:
                await manager.broadcast({"threats": [threat]})
            return JSONResponse({"sent": True, "type": "threat"})

        # no explicit payload: emit a sample packet
        sample_packet = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.250",
            "dst_port": 8080,
            "protocol": "TCP",
            "severity": "normal",
        }
        manager.add_packet_to_history(sample_packet)
        if _BROADCAST_QUEUE is not None:
            await _BROADCAST_QUEUE.put({"packet": sample_packet})
        else:
            await manager.broadcast({"packet": sample_packet})
        manager.network_graph.add_traffic(sample_packet['src_ip'], sample_packet['dst_port'])
        if _BROADCAST_QUEUE is not None:
            await _BROADCAST_QUEUE.put({"graph": manager.network_graph.to_dict()})
        else:
            await manager.broadcast({"graph": manager.network_graph.to_dict()})
        return JSONResponse({"sent": True, "type": "sample_packet", "packet": sample_packet})
    except Exception as e:
        logger.error(f"admin_emit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Mount the static files directory to serve the frontend
app.mount("/static", StaticFiles(directory="frontend/build/static"), name="static-assets")
app.mount("/", StaticFiles(directory="frontend/build", html=True), name="root")
