#!/usr/bin/env python3
"""
CyBrain Brain Orchestrator
Async orchestrator for real-time threat detection using eBPF telemetry
"""

import asyncio
import json
import os
import pickle
import signal
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

import numpy as np
import onnxruntime as ort
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv, global_mean_pool
from sentence_transformers import SentenceTransformer

# Create logs directory
os.makedirs('logs', exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define GNN model
class GNN(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, embed_dim, out_channels):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.lin = torch.nn.Linear(hidden_channels + embed_dim, out_channels)

    def forward(self, x, edge_index, batch, embed):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        pooled = global_mean_pool(x, batch)
        x = torch.cat([pooled, embed], dim=1)
        out = self.lin(x)
        return out

class CyBrainOrchestrator:
    def __init__(self):
        self.workspace = Path(__file__).parent.parent
        self.data_dir = self.workspace / "data"
        self.models_dir = self.workspace / "agents" / "models"
        self.utils_dir = self.workspace / "agents" / "utils"
        self.logs_dir = self.workspace / "logs"

        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)

        # Load models and utilities
        self._load_models()
        self._load_mitre_data()

        # Global counters
        self.total_logs = 0
        self.blocked_alerts = 0

        # Alert storage
        self.alerts_file = self.data_dir / "alerts.json"
        self.wazuh_file = self.logs_dir / "wazuh_alerts.json"

    def _load_models(self):
        """Load ML models and preprocessing utilities"""
        try:
            # Load ONNX autoencoder
            self.onnx_session = ort.InferenceSession(str(self.models_dir / "vrains_autoencoder.onnx"))

            # Load PyTorch GNN
            self.gnn_model = GNN(18, 64, 384, 384)
            self.gnn_model.load_state_dict(torch.load(str(self.models_dir / "vrains_gnn_model.pth")))
            self.gnn_model.eval()

            # Load preprocessing
            with open(self.utils_dir / "encoders.pkl", "rb") as f:
                self.encoders = pickle.load(f)
            with open(self.utils_dir / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)

            # Load SentenceTransformer for MITRE embeddings
            self.embedder = SentenceTransformer('all-MiniLM-L6-v2')

            logger.info("Models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            sys.exit(1)

    def _load_mitre_data(self):
        """Load MITRE ATT&CK data"""
        try:
            self.mitre_techniques = {
                "T1003": {"name": "OS Credential Dumping", "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.", "tactic": "Credential Access"},
                "T1048": {"name": "Exfiltration Over Alternative Protocol", "description": "Adversaries may steal data by exfiltrating it over a different protocol than the one used for initial command and control or to bypass network-based detection methods.", "tactic": "Exfiltration"},
                "T1059": {"name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.", "tactic": "Execution"},
                "T1486": {"name": "Data Encrypted for Impact", "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.", "tactic": "Impact"}
            }
            self.technique_embeddings = {}
            # Embed descriptions
            for tid, info in self.mitre_techniques.items():
                self.technique_embeddings[tid] = self.embedder.encode(info["description"])

            logger.info(f"Loaded {len(self.mitre_techniques)} MITRE techniques")
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            self.mitre_techniques = {}
            self.technique_embeddings = {}

    def _extract_features(self, event: Dict) -> Optional[List]:
        """Extract 9 features from Tetragon event, matching gnn.py"""
        try:
            if 'process_kprobe' not in event:
                return None
            process = event['process_kprobe']['process']
            parent = event['process_kprobe'].get('parent', {})
            exec_id = process['exec_id']
            parent_exec_id = parent.get('exec_id', '')
            binary = process.get('binary', '')
            arguments = process.get('arguments', '')
            uid = process.get('uid', 0)
            cwd = process.get('cwd', '')
            arg_count = len(arguments.split()) if arguments else 0
            time_str = event['time']
            from datetime import datetime
            try:
                time_ts = datetime.fromisoformat(time_str[:-1]).timestamp()
            except:
                time_ts = 0.0
            auid = process.get('auid', 0)
            return [exec_id, parent_exec_id, binary, arguments, uid, cwd, arg_count, time_ts, auid]
        except Exception as e:
            logger.error(f"Failed to extract features: {e}")
            return None

    def _preprocess_vector(self, features: List) -> np.ndarray:
        """Preprocess 9 features using loaded encoders and scaler, pad to 18"""
        try:
            encoded = []
            for i, val in enumerate(features):
                if i in [4, 7]:  # uid, time_ts - keep as is
                    encoded.append(val)
                elif i in [0, 1, 2, 3, 5, 6, 8]:  # strings to encode
                    if i in self.encoders:
                        if val not in self.encoders[i].classes_:
                            encoded.append(self.encoders[i].transform(['unknown'])[0])
                        else:
                            encoded.append(self.encoders[i].transform([val])[0])
                    else:
                        encoded.append(0)  # fallback
            # Scale
            scaled = self.scaler.transform([encoded])
            # Pad to 18
            padded = np.pad(scaled[0], (0, 9), 'constant')
            return padded.astype(np.float32).reshape(1, -1)
        except Exception as e:
            logger.error(f"Failed to preprocess vector: {e}")
            return np.zeros((1, 18), dtype=np.float32)

    def _detect_anomaly(self, vector: np.ndarray) -> float:
        """Run anomaly detection using autoencoder"""
        try:
            # Run inference
            outputs = self.onnx_session.run(None, {"input": vector})
            reconstruction = outputs[0]

            # Calculate MSE
            mse = np.mean((vector - reconstruction) ** 2)
            return float(mse)
        except Exception as e:
            logger.error(f"Failed anomaly detection: {e}")
            return 0.0

    def _build_graph(self, event: Dict) -> Optional[Data]:
        """Build torch_geometric Data from event"""
        try:
            if 'process_kprobe' not in event:
                return None
            process = event['process_kprobe']['process']
            parent = event['process_kprobe'].get('parent', {})

            # Features for process
            process_features = self._preprocess_vector(self._extract_features(event))[0]

            nodes = [process_features]
            edges = []

            if parent:
                # Features for parent (simplified)
                parent_features = [
                    parent.get('exec_id', ''),
                    '',  # parent_exec_id
                    parent.get('binary', ''),
                    '',  # arguments
                    parent.get('uid', 0),
                    '',  # cwd
                    0,   # arg_count
                    0.0, # time_ts
                    parent.get('auid', 0)
                ]
                parent_features = self._preprocess_vector(parent_features)[0]
                nodes.append(parent_features)
                edges.append([1, 0])  # parent to process

            x = torch.tensor(nodes, dtype=torch.float)
            edge_index = torch.tensor(edges, dtype=torch.long).t() if edges else torch.empty(2, 0, dtype=torch.long)
            batch = torch.zeros(len(nodes), dtype=torch.long)

            return Data(x=x, edge_index=edge_index, batch=batch)
        except Exception as e:
            logger.error(f"Failed to build graph: {e}")
            return None

    def _analyze_with_gnn(self, graph: Data) -> Dict:
        """Analyze with GNN for MITRE mapping using embedding similarity"""
        try:
            # Zero embed for inference
            zero_embed = torch.zeros(1, 384)
            with torch.no_grad():
                out_embed = self.gnn_model(graph.x, graph.edge_index, graph.batch, zero_embed)
                out_embed = out_embed.squeeze()  # [384]

                # Compute similarity to all technique embeddings
                similarities = {}
                for tid, tech_embed in self.technique_embeddings.items():
                    tech_embed = torch.tensor(tech_embed, dtype=torch.float)
                    sim = F.cosine_similarity(out_embed, tech_embed, dim=0).item()
                    similarities[tid] = sim

                # Find best match
                best_tid = max(similarities, key=similarities.get)
                confidence = similarities[best_tid]

                technique_info = self.mitre_techniques.get(best_tid, {})
                return {
                    "technique": best_tid,
                    "confidence": confidence,
                    "tactic": technique_info.get("tactic", "Unknown"),
                    "description": technique_info.get("description", "")
                }
        except Exception as e:
            logger.error(f"Failed GNN analysis: {e}")
            return {
                "technique": "Error",
                "confidence": 0.0,
                "tactic": "Error",
                "description": "Analysis failed"
            }

    def _send_sigstop(self, pid: int):
        """Send SIGSTOP to process"""
        try:
            os.kill(pid, signal.SIGSTOP)
            logger.info(f"Sent SIGSTOP to PID {pid}")
            self.blocked_alerts += 1
        except Exception as e:
            logger.error(f"Failed to send SIGSTOP to {pid}: {e}")

    def _save_alert(self, event: Dict, mse: float, mitre_info: Dict):
        """Save alert to files"""
        try:
            alert = {
                "timestamp": event.get("time", ""),
                "event": event,
                "mse": mse,
                "mitre": mitre_info,
                "action": "blocked" if mse > 0.05 else "monitored"
            }

            # Save full alert
            alerts = []
            if self.alerts_file.exists():
                try:
                    with open(self.alerts_file, "r") as f:
                        alerts = json.load(f)
                except:
                    alerts = []

            alerts.append(alert)
            with open(self.alerts_file, "w") as f:
                json.dump(alerts, f, indent=2)

            # Save Wazuh format
            wazuh_alert = {
                "timestamp": event.get("time", ""),
                "rule": {
                    "id": "cybrain_anomaly",
                    "level": 12 if mse > 0.05 else 5,
                    "description": f"CyBrain Anomaly Detection - {mitre_info.get('technique', 'Unknown')}"
                },
                "agent": {
                    "id": "cybrain",
                    "name": "CyBrain-EDR"
                },
                "data": {
                    "mse": mse,
                    "technique": mitre_info.get("technique"),
                    "confidence": mitre_info.get("confidence"),
                    "pid": event.get("process_kprobe", {}).get("process", {}).get("pid")
                }
            }

            with open(self.wazuh_file, "a") as f:
                f.write(json.dumps(wazuh_alert) + "\n")

        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    async def _process_event(self, event: Dict):
        """Process a single Tetragon event"""
        try:
            self.total_logs += 1

            # Extract and preprocess features
            features = self._extract_features(event)
            if features is None:
                return

            vector = self._preprocess_vector(features)

            # Anomaly detection
            mse = self._detect_anomaly(vector)

            if mse > 0.05:
                # Block process
                pid = None
                try:
                    pid = event['process_kprobe']['process']['pid']
                except KeyError:
                    pass
                if pid:
                    self._send_sigstop(pid)

                # GNN analysis
                graph = self._build_graph(event)
                if graph is not None:
                    mitre_info = self._analyze_with_gnn(graph)
                else:
                    mitre_info = {
                        "technique": "Graph Build Failed",
                        "confidence": 0.0,
                        "tactic": "Error",
                        "description": "Failed to build graph for analysis"
                    }
            else:
                mitre_info = {
                    "technique": "Normal",
                    "confidence": 1.0,
                    "tactic": "Normal",
                    "description": "Normal behavior"
                }

            # Save alert
            self._save_alert(event, mse, mitre_info)

            logger.info(f"Processed event - MSE: {mse:.4f}, Technique: {mitre_info.get('technique')}")

        except Exception as e:
            logger.error(f"Failed to process event: {e}")

    async def _monitor_tetragon(self):
        """Monitor Tetragon events asynchronously"""
        try:
            # Start tetragon process
            process = await asyncio.create_subprocess_exec(
                "sudo", "tetra", "getevents", "-o", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            logger.info("Started monitoring Tetragon events")

            # Read stdout line by line
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                try:
                    event = json.loads(line.decode().strip())
                    await self._process_event(event)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON received from Tetragon")
                    continue

        except Exception as e:
            logger.error(f"Failed to monitor Tetragon: {e}")
            logger.error("Make sure Tetragon is installed and running")

    async def run(self):
        """Main orchestrator loop"""
        logger.info("CyBrain Orchestrator starting...")

        try:
            await self._monitor_tetragon()
        except KeyboardInterrupt:
            logger.info("Orchestrator stopped by user")
        except Exception as e:
            logger.error(f"Orchestrator error: {e}")
        finally:
            logger.info(f"Session summary - Total logs: {self.total_logs}, Blocked alerts: {self.blocked_alerts}")

if __name__ == "__main__":
    orchestrator = CyBrainOrchestrator()
    asyncio.run(orchestrator.run())
