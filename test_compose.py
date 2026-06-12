import sys
import os
from docksec.compose_scanner import ComposeOrchestrator

orchestrator = ComposeOrchestrator('docker-compose.yml', scan_only=True)
results = orchestrator.run_full_scan()
import json
print(json.dumps(results['json_data'], indent=2))
