#!/usr/bin/env python3
"""
CAPEv2 Malware Analysis Automation Script
Automates submission, monitoring, and retrieval of malware analysis results
"""

import os
import time
import json
import shutil
import requests
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cape_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TaskInfo:
    task_id: str
    sample_path: Path
    vm_name: str
    submission_time: float
    status: str = "submitted"

class CAPEAutomation:
    def __init__(self, base_dir: str = "/home/cape/Documents", folder_prefixes=None):
        self.base_dir = Path(base_dir)
        self.cape_dir = Path("/opt/CAPEv2")
        self.cape_storage = Path("/opt/CAPEv2/storage/analyses")
        self.cape_api = "http://127.0.0.1:8000/apiv2"
        
        # Default to common malware types, or use provided prefixes
        if folder_prefixes is None:
            self.folder_prefixes = ["Infostealer", "Adware", "Banker", "Downloader","RAT","Ransomware","DDoS","Miner","Benign"]
        elif isinstance(folder_prefixes, str):
            self.folder_prefixes = [folder_prefixes]  # Single prefix as string
        else:
            self.folder_prefixes = folder_prefixes  # List of prefixes
        
        # VM configuration
        self.vms = ["HEY", "HEY_2", "HEY_3"]
        self.vm_status = {vm: "idle" for vm in self.vms}
        
        # Task tracking with thread safety
        self.active_tasks: Dict[str, TaskInfo] = {}
        self.completed_tasks: List[TaskInfo] = []
        self.failed_tasks: List[TaskInfo] = []
        self.lock = threading.RLock()  # Reentrant lock for nested operations
        
        # Current folder being processed
        self.current_folder = None
        self.processed_dir = None
        self.json_dir = None
        self.failed_dir = None
        
        logger.info(f"CAPEv2 Automation initialized - Base dir: {self.base_dir}")
        logger.info(f"VMs available: {', '.join(self.vms)}")

    def discover_folders(self) -> List[Path]:
        """Discover malware type folders in base directory"""
        folders = []
        if not self.base_dir.exists():
            logger.error(f"Base directory {self.base_dir} does not exist!")
            return folders
        
        logger.info(f"Looking for folders with prefixes: {self.folder_prefixes}")
        
        for item in self.base_dir.iterdir():
            if item.is_dir() and '_' in item.name:
                # Check if it matches any of the specified prefixes with pattern like Prefix_1, Prefix_2, etc.
                parts = item.name.split('_')
                if len(parts) == 2 and parts[1].isdigit():
                    prefix = parts[0]
                    # Check if this prefix matches any of our target prefixes (case insensitive)
                    if any(prefix.lower() == target_prefix.lower() for target_prefix in self.folder_prefixes):
                        folders.append(item)
        
        folders.sort()
        logger.info(f"Discovered folders: {[f.name for f in folders]}")
        return folders

    def setup_output_directories(self, folder_name: str):
        """Create output directories for the current folder"""
        base_name = folder_name
        
        self.processed_dir = self.base_dir / f"{base_name}_processed"
        self.json_dir = self.base_dir / f"{base_name}_json"
        self.failed_dir = self.base_dir / f"{base_name}_failed"
        
        for dir_path in [self.processed_dir, self.json_dir, self.failed_dir]:
            dir_path.mkdir(exist_ok=True)
            logger.info(f"Created directory: {dir_path}")

    def get_samples(self, folder_path: Path) -> List[Path]:
        """Get all .exe samples from folder"""
        if not folder_path.exists():
            return []
        
        samples = [f for f in folder_path.iterdir() if f.suffix.lower() == '.exe' and f.is_file()]
        logger.info(f"Found {len(samples)} samples in {folder_path.name}")
        return sorted(samples)

    def get_vm_status(self) -> Dict[str, str]:
        """Get current status of all VMs via API"""
        try:
            response = requests.get(f"{self.cape_api}/tasks/list/", timeout=10)
            if response.status_code != 200:
                logger.warning(f"Failed to get VM status: HTTP {response.status_code}")
                return self.vm_status
            
            data = response.json()
            tasks = data.get('data', [])
            
            # Reset VM status
            vm_status = {vm: "idle" for vm in self.vms}
            
            # Check which VMs are busy (only pending and running tasks occupy VMs)
            for task in tasks:
                if task.get('status') in ['pending', 'running']:
                    machine = task.get('machine')
                    if machine in self.vms:
                        vm_status[machine] = "busy"
            
            return vm_status
            
        except Exception as e:
            logger.warning(f"Error getting VM status: {e}")
            return self.vm_status

    def get_available_vm(self) -> Optional[str]:
        """Get an available VM name"""
        vm_status = self.get_vm_status()
        
        with self.lock:
            for vm_name in self.vms:
                if vm_status.get(vm_name) == "idle":
                    # Check if this VM has any tasks in pending/running status
                    vm_busy = any(
                        task.vm_name == vm_name and task.status in ['submitted', 'pending', 'running']
                        for task in self.active_tasks.values()
                    )
                    if not vm_busy:
                        return vm_name
        return None

    def submit_sample(self, sample_path: Path, vm_name: Optional[str] = None) -> Optional[str]:
        """Submit a sample to CAPEv2"""
        cmd = [
            "poetry", "run", "python3", "utils/submit.py",
            str(sample_path),
            "--route", "inetsim"
        ]
        
        if vm_name:
            cmd.extend(["--machine", vm_name])
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=str(self.cape_dir), 
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Submission failed for {sample_path.name}: {result.stderr.strip()}")
                return None
            
            # Extract task ID from output
            for line in result.stdout.splitlines():
                if "added as task with ID" in line:
                    import re
                    task_ids = re.findall(r'\d+', line)
                    if task_ids:
                        task_id = task_ids[-1]
                        logger.info(f"Submitted {sample_path.name} as task {task_id} on {vm_name or 'any VM'}")
                        return task_id
            
            logger.error(f"Could not extract task ID for {sample_path.name}")
            return None
            
        except subprocess.TimeoutExpired:
            logger.error(f"Submission timeout for {sample_path.name}")
            return None
        except Exception as e:
            logger.error(f"Submission error for {sample_path.name}: {e}")
            return None

    def get_task_status(self, task_id: str) -> Optional[str]:
        """Get status of a specific task"""
        try:
            response = requests.get(f"{self.cape_api}/tasks/view/{task_id}/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                status = data.get('data', {}).get('status', 'unknown')
                return status
            else:
                logger.warning(f"Failed to get task {task_id} status: HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.warning(f"Error getting task {task_id} status: {e}")
            return None

    def retrieve_json_report(self, task_id: str, sample_name: str) -> bool:
        """Retrieve and save JSON report for completed task"""
        report_path = self.cape_storage / task_id / "reports" / "report.json"
        
        if not report_path.exists():
            logger.warning(f"Report not found for task {task_id}")
            return False
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = self.json_dir / f"task_{task_id}_{sample_name}_{timestamp}.json"
            
            shutil.copy2(report_path, dest_path)
            logger.info(f"Retrieved JSON report for task {task_id}: {dest_path}")
            
            # Delete PCAP file to save space
            self.delete_pcap(task_id)
            return True
            
        except Exception as e:
            logger.error(f"Failed to retrieve report for task {task_id}: {e}")
            return False

    def delete_pcap(self, task_id: str):
        """Delete PCAP file to save disk space"""
        pcap_path = self.cape_storage / task_id / "dump.pcap"
        if pcap_path.exists():
            try:
                pcap_path.unlink()
                logger.debug(f"Deleted PCAP for task {task_id}")
            except Exception as e:
                logger.warning(f"Failed to delete PCAP for task {task_id}: {e}")

    def move_processed_sample(self, sample_path: Path, task_id: str):
        """Move processed sample to processed directory"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = self.processed_dir / f"task_{task_id}_{sample_path.name}_{timestamp}"
            
            if sample_path.exists():
                shutil.move(str(sample_path), str(dest_path))
                logger.info(f"Moved processed sample: {sample_path.name} -> {dest_path}")
            else:
                logger.warning(f"Sample {sample_path.name} no longer exists")
                
        except Exception as e:
            logger.error(f"Failed to move processed sample {sample_path.name}: {e}")

    def move_failed_sample(self, sample_path: Path, reason: str):
        """Move failed sample to failed directory"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = self.failed_dir / f"failed_{reason}_{sample_path.name}_{timestamp}"
            
            if sample_path.exists():
                shutil.move(str(sample_path), str(dest_path))
                logger.warning(f"Moved failed sample: {sample_path.name} -> {dest_path} (reason: {reason})")
            else:
                logger.warning(f"Failed sample {sample_path.name} no longer exists")
                
        except Exception as e:
            logger.error(f"Failed to move failed sample {sample_path.name}: {e}")

    def monitor_tasks(self):
        """Monitor active tasks and update their status"""
        with self.lock:
            tasks_to_remove = []
            
            for task_id, task_info in self.active_tasks.items():
                current_status = self.get_task_status(task_id)
                
                if current_status is None:
                    continue
                
                previous_status = task_info.status
                task_info.status = current_status
                
                if current_status != previous_status:
                    logger.info(f"Task {task_id} status changed: {previous_status} -> {current_status}")
                
                if current_status == "completed":
                    # VM is now free! Analysis finished, CAPE is generating JSON report
                    # We can submit new samples to this VM, but keep tracking this task
                    logger.info(f"🟢 VM {task_info.vm_name} freed! Task {task_id} completed analysis, generating report: {task_info.sample_path.name}")
                    # Don't remove from active_tasks yet, keep monitoring until "reported"
                
                elif current_status == "reported":
                    # JSON report is ready for retrieval
                    success = self.retrieve_json_report(task_id, task_info.sample_path.name)
                    if success:
                        self.move_processed_sample(task_info.sample_path, task_id)
                        self.completed_tasks.append(task_info)
                        logger.info(f"✅ Retrieved and processed task {task_id}: {task_info.sample_path.name}")
                    else:
                        self.move_failed_sample(task_info.sample_path, "report_retrieval_failed")
                        self.failed_tasks.append(task_info)
                        logger.error(f"✗ Failed to retrieve report for task {task_id}")
                    
                    tasks_to_remove.append(task_id)
                
                elif current_status in ["failed_analysis", "failed_processing", "failed_reporting"]:
                    # Task failed
                    self.move_failed_sample(task_info.sample_path, current_status)
                    self.failed_tasks.append(task_info)
                    logger.warning(f"✗ Failed task {task_id}: {task_info.sample_path.name} ({current_status})")
                    tasks_to_remove.append(task_id)
            
            # Remove completed/failed tasks
            for task_id in tasks_to_remove:
                del self.active_tasks[task_id]

    def submit_next_sample(self, samples_queue: List[Path]) -> bool:
        """Submit next available sample if VM is available"""
        if not samples_queue:
            return False
        
        available_vm = self.get_available_vm()
        if not available_vm:
            return False
        
        with self.lock:
            # Double-check we still have samples and VM is available
            if not samples_queue:
                return False
            
            sample_path = samples_queue.pop(0)
            task_id = self.submit_sample(sample_path, available_vm)
            
            if task_id:
                # Track the task
                task_info = TaskInfo(
                    task_id=task_id,
                    sample_path=sample_path,
                    vm_name=available_vm,
                    submission_time=time.time()
                )
                self.active_tasks[task_id] = task_info
                self.vm_status[available_vm] = "busy"
                return True
            else:
                # Submission failed
                self.move_failed_sample(sample_path, "submission_failed")
                return False

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_status(self):
        """Print current processing status (clears screen first to save memory)"""
        # Clear screen to prevent memory buildup from terminal buffer
        self.clear_screen()
        
        with self.lock:
            active_count = len(self.active_tasks)
            completed_count = len(self.completed_tasks)
            failed_count = len(self.failed_tasks)
        
        vm_status = self.get_vm_status()
        
        print(f"{'='*60}")
        print(f"STATUS UPDATE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.current_folder:
            print(f"Processing folder: {self.current_folder}")
        print(f"{'='*60}")
        
        print("VM Status:")
        for vm_name in self.vms:
            status = vm_status.get(vm_name, "unknown")
            status_icon = "🟢" if status == "idle" else "🔴"
            print(f"  {status_icon} {vm_name}: {status}")
        
        print(f"\nTask Summary:")
        print(f"  Active: {active_count}")
        print(f"  Completed: {completed_count}")
        print(f"  Failed: {failed_count}")
        
        if active_count > 0:
            print(f"\nActive Tasks:")
            with self.lock:
                for task_id, task_info in list(self.active_tasks.items())[:5]:  # Show first 5
                    duration = int(time.time() - task_info.submission_time)
                    print(f"  Task {task_id}: {task_info.sample_path.name} on {task_info.vm_name} ({duration}s)")
                if len(self.active_tasks) > 5:
                    print(f"  ... and {len(self.active_tasks) - 5} more")
        
        print(f"{'='*60}")
        print("Press Ctrl+C to stop")

    def process_folder(self, folder_path: Path) -> bool:
        """Process all samples in a folder"""
        self.current_folder = folder_path.name
        self.setup_output_directories(folder_path.name)
        
        # Reset counters for new folder
        with self.lock:
            self.active_tasks.clear()
            self.completed_tasks.clear()
            self.failed_tasks.clear()
        
        samples = self.get_samples(folder_path)
        if not samples:
            logger.info(f"No samples found in {folder_path.name}")
            return True
        
        logger.info(f"Starting to process {len(samples)} samples from {folder_path.name}")
        
        # Create a working queue of samples
        samples_queue = samples.copy()
        
        # Initial submission burst (fill all available VMs)
        initial_submissions = 0
        for _ in range(len(self.vms)):
            if self.submit_next_sample(samples_queue):
                initial_submissions += 1
        
        logger.info(f"Initial submissions: {initial_submissions}")
        
        # Main processing loop
        last_status_print = 0
        while True:
            current_time = time.time()
            
            # Monitor active tasks
            self.monitor_tasks()
            
            # Try to submit more samples
            submitted = False
            while self.submit_next_sample(samples_queue):
                submitted = True
            
            # Print status every minute
            if current_time - last_status_print >= 60:  # 60 seconds
                self.print_status()
                last_status_print = current_time
            
            # Check if we're done
            with self.lock:
                active_count = len(self.active_tasks)
                remaining_samples = len(samples_queue)
            
            if active_count == 0 and remaining_samples == 0:
                logger.info(f"Completed processing folder {folder_path.name}")
                break
            
            # Sleep for a bit before next iteration
            time.sleep(10)  # Check every 10 seconds
        
        # Final status
        self.print_folder_summary()
        return True

    def print_folder_summary(self):
        """Print summary for completed folder"""
        with self.lock:
            completed_count = len(self.completed_tasks)
            failed_count = len(self.failed_tasks)
            total_count = completed_count + failed_count
        
        print(f"\n{'='*60}")
        print(f"FOLDER COMPLETED: {self.current_folder}")
        print(f"{'='*60}")
        print(f"Total samples processed: {total_count}")
        print(f"Successfully completed: {completed_count}")
        print(f"Failed: {failed_count}")
        if total_count > 0:
            print(f"Success rate: {(completed_count/total_count)*100:.1f}%")
        
        if completed_count > 0:
            durations = []
            with self.lock:
                for task in self.completed_tasks:
                    if hasattr(task, 'completion_time'):
                        duration = task.completion_time - task.submission_time
                        durations.append(duration)
            
            if durations:
                avg_duration = sum(durations) / len(durations)
                print(f"Average processing time: {avg_duration/60:.1f} minutes")
        
        print(f"\nOutput locations:")
        print(f"  JSON reports: {self.json_dir}")
        print(f"  Processed samples: {self.processed_dir}")
        print(f"  Failed samples: {self.failed_dir}")
        print(f"{'='*60}\n")

    def run(self):
        """Main execution loop"""
        logger.info("Starting CAPEv2 Automation")
        
        folders = self.discover_folders()
        if not folders:
            logger.error("No folders found to process")
            return
        
        for folder in folders:
            samples = self.get_samples(folder)
            if samples:
                logger.info(f"Processing folder: {folder.name} ({len(samples)} samples)")
                self.process_folder(folder)
            else:
                logger.info(f"Skipping empty folder: {folder.name}")
        
        logger.info("CAPEv2 Automation completed")

def main():
    # Example usage - process only Downloader folders
    automation = CAPEAutomation("/home/cape/Documents", 
                               folder_prefixes="Downloader")
    
    try:
        automation.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise

if __name__ == "__main__":
    main()
