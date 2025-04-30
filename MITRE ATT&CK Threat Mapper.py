"""
MITRE ATT&CK Threat Mapper

This application:
1. Fetches the latest MITRE ATT&CK framework data
2. Maps malware samples to relevant ATT&CK techniques
3. Generates visualizations and reports for threat analysis
4. Creates custom red team playbooks based on the mappings
"""

import requests
import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import argparse
from typing import Dict, List, Any, Optional, Union


class MitreAttackAPI:
    """
    Class to interact with the MITRE ATT&CK API
    """
    
    def __init__(self, base_url: str = "https://attack.mitre.org/api/"):
        self.base_url = base_url
        self.techniques = {}
        self.tactics = {}
        self.software = {}  # Includes malware and tools
        self.groups = {}
        self.cache_dir = "cache"
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _get_cached_data(self, cache_file: str) -> Optional[Dict]:
        """Get data from cache if available and recent."""
        cache_path = os.path.join(self.cache_dir, cache_file)
        if os.path.exists(cache_path):
            # Check if cache is less than 1 day old
            file_time = os.path.getmtime(cache_path)
            if (datetime.now().timestamp() - file_time) < 86400:  # 24 hours
                try:
                    with open(cache_path, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    print(f"Error reading cache: {e}")
        return None
    
    def _save_to_cache(self, data: Dict, cache_file: str) -> None:
        """Save data to cache."""
        cache_path = os.path.join(self.cache_dir, cache_file)
        with open(cache_path, 'w') as f:
            json.dump(data, f)
    
    def fetch_techniques(self, use_cache: bool = True) -> Dict[str, Any]:
        """Fetch all ATT&CK techniques."""
        if use_cache:
            cached = self._get_cached_data("techniques.json")
            if cached:
                self.techniques = cached
                return cached
        
        try:
            response = requests.get(f"{self.base_url}techniques/enterprise/")
            data = response.json()
            
            # Process and organize techniques
            techniques_dict = {technique["technique_id"]: technique for technique in data}
            self.techniques = techniques_dict
            
            # Cache the results
            self._save_to_cache(techniques_dict, "techniques.json")
            
            return techniques_dict
        except Exception as e:
            print(f"Error fetching techniques: {e}")
            return {}
    
    def fetch_tactics(self, use_cache: bool = True) -> Dict[str, Any]:
        """Fetch all ATT&CK tactics."""
        if use_cache:
            cached = self._get_cached_data("tactics.json")
            if cached:
                self.tactics = cached
                return cached
        
        try:
            response = requests.get(f"{self.base_url}tactics/enterprise/")
            data = response.json()
            
            # Process and organize tactics
            tactics_dict = {tactic["tactic_id"]: tactic for tactic in data}
            self.tactics = tactics_dict
            
            # Cache the results
            self._save_to_cache(tactics_dict, "tactics.json")
            
            return tactics_dict
        except Exception as e:
            print(f"Error fetching tactics: {e}")
            return {}
    
    def fetch_software(self, use_cache: bool = True) -> Dict[str, Any]:
        """Fetch all ATT&CK software (malware and tools)."""
        if use_cache:
            cached = self._get_cached_data("software.json")
            if cached:
                self.software = cached
                return cached
        
        try:
            response = requests.get(f"{self.base_url}software/")
            data = response.json()
            
            # Process and organize software
            software_dict = {item["software_id"]: item for item in data}
            self.software = software_dict
            
            # Cache the results
            self._save_to_cache(software_dict, "software.json")
            
            return software_dict
        except Exception as e:
            print(f"Error fetching software: {e}")
            return {}
    
    def fetch_groups(self, use_cache: bool = True) -> Dict[str, Any]:
        """Fetch all ATT&CK groups (threat actors)."""
        if use_cache:
            cached = self._get_cached_data("groups.json")
            if cached:
                self.groups = cached
                return cached
        
        try:
            response = requests.get(f"{self.base_url}groups/")
            data = response.json()
            
            # Process and organize groups
            groups_dict = {group["group_id"]: group for group in data}
            self.groups = groups_dict
            
            # Cache the results
            self._save_to_cache(groups_dict, "groups.json")
            
            return groups_dict
        except Exception as e:
            print(f"Error fetching groups: {e}")
            return {}
    
    def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific technique."""
        if not self.techniques:
            self.fetch_techniques()
        
        if technique_id in self.techniques:
            return self.techniques[technique_id]
        
        # If not found in cache, fetch directly
        try:
            response = requests.get(f"{self.base_url}techniques/{technique_id}/")
            return response.json()
        except Exception as e:
            print(f"Error fetching technique {technique_id}: {e}")
            return {}
    
    def get_software_by_name(self, name: str) -> List[Dict[str, Any]]:
        """Find software (malware or tools) by name."""
        if not self.software:
            self.fetch_software()
        
        results = []
        name_lower = name.lower()
        for software_id, software in self.software.items():
            if name_lower in software["name"].lower():
                results.append(software)
        
        return results
    
    def get_techniques_used_by_software(self, software_id: str) -> List[Dict[str, Any]]:
        """Get techniques used by a specific software."""
        if not self.software:
            self.fetch_software()
        
        if software_id not in self.software:
            print(f"Software {software_id} not found")
            return []
        
        software = self.software[software_id]
        techniques = []
        
        # Extract technique IDs from the software data
        if "technique_refs" in software:
            for technique_id in software["technique_refs"]:
                technique = self.get_technique_details(technique_id)
                if technique:
                    techniques.append(technique)
        
        return techniques


class ThreatMapper:
    """
    Maps detected malware to MITRE ATT&CK techniques
    """
    
    def __init__(self):
        self.mitre_api = MitreAttackAPI()
        # Load all necessary data
        self.mitre_api.fetch_techniques()
        self.mitre_api.fetch_tactics()
        self.mitre_api.fetch_software()
        self.mitre_api.fetch_groups()
    
    def map_malware_to_techniques(self, malware_name: str) -> Dict[str, Any]:
        """Map a malware to its ATT&CK techniques."""
        result = {
            "malware_name": malware_name,
            "matched_software": [],
            "techniques": [],
            "tactics": set(),
            "timestamp": datetime.now().isoformat()
        }
        
        # Find software matching the malware name
        software_matches = self.mitre_api.get_software_by_name(malware_name)
        
        for software in software_matches:
            result["matched_software"].append({
                "id": software["software_id"],
                "name": software["name"],
                "type": software.get("type", "unknown"),
                "description": software.get("description", "")
            })
            
            # Get techniques used by this software
            techniques = self.mitre_api.get_techniques_used_by_software(software["software_id"])
            
            for technique in techniques:
                technique_data = {
                    "id": technique["technique_id"],
                    "name": technique["name"],
                    "description": technique.get("description", ""),
                    "tactic": technique.get("tactic", "unknown")
                }
                
                # Add tactic information
                if "tactic_refs" in technique:
                    tactic_names = []
                    for tactic_id in technique["tactic_refs"]:
                        if tactic_id in self.mitre_api.tactics:
                            tactic_name = self.mitre_api.tactics[tactic_id]["name"]
                            tactic_names.append(tactic_name)
                            result["tactics"].add(tactic_name)
                    
                    technique_data["tactics"] = tactic_names
                
                result["techniques"].append(technique_data)
        
        # Convert tactics set to list for JSON serialization
        result["tactics"] = list(result["tactics"])
        
        return result
    
    def generate_report(self, mapping_result: Dict[str, Any], output_format: str = "text") -> str:
        """Generate a report from the mapping results."""
        malware_name = mapping_result["malware_name"]
        matched_software = mapping_result["matched_software"]
        techniques = mapping_result["techniques"]
        tactics = mapping_result["tactics"]
        
        if output_format == "text":
            report = f"# Threat Intelligence Report: {malware_name}\n\n"
            report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            report += "## Matched Malware/Software\n\n"
            if matched_software:
                for software in matched_software:
                    report += f"- **{software['name']}** ({software['id']})\n"
                    report += f"  Type: {software['type']}\n"
                    report += f"  Description: {software['description'][:200]}...\n\n"
            else:
                report += "No matching software found in the MITRE ATT&CK database.\n\n"
            
            report += "## ATT&CK Tactics Used\n\n"
            if tactics:
                for tactic in tactics:
                    report += f"- {tactic}\n"
            else:
                report += "No tactics identified.\n\n"
            
            report += "## ATT&CK Techniques Used\n\n"
            if techniques:
                for technique in techniques:
                    report += f"- **{technique['name']}** ({technique['id']})\n"
                    if "tactics" in technique:
                        report += f"  Tactics: {', '.join(technique['tactics'])}\n"
                    report += f"  Description: {technique['description'][:200]}...\n\n"
            else:
                report += "No techniques identified.\n\n"
            
            report += "## Recommendations\n\n"
            report += "Based on the identified techniques, consider implementing these mitigations:\n\n"
            
            # Simplified example recommendations
            common_mitigations = {
                "Initial Access": "Implement multi-factor authentication and security awareness training.",
                "Execution": "Use application whitelisting and script execution controls.",
                "Persistence": "Monitor registry and startup folders for unauthorized changes.",
                "Privilege Escalation": "Apply principle of least privilege and patch vulnerabilities.",
                "Defense Evasion": "Use EDR solutions and monitor for suspicious process behaviors.",
                "Credential Access": "Implement credential protection and monitor for credential dumping.",
                "Discovery": "Monitor for unusual network and system discovery activities.",
                "Lateral Movement": "Segment networks and implement proper authentication controls.",
                "Collection": "Monitor for unusual data access patterns.",
                "Command and Control": "Implement network monitoring and traffic analysis.",
                "Exfiltration": "Monitor for unusual outbound data transfers.",
                "Impact": "Maintain backups and implement business continuity plans."
            }
            
            for tactic in tactics:
                if tactic in common_mitigations:
                    report += f"- **{tactic}**: {common_mitigations[tactic]}\n"
            
            return report
        
        elif output_format == "json":
            # Already in a structured format, just return as JSON string
            return json.dumps(mapping_result, indent=2)
        
        else:
            return "Unsupported output format"
    
    def visualize_techniques(self, mapping_result: Dict[str, Any], output_file: str = "attack_heatmap.png") -> str:
        """Create visualization of techniques by tactic."""
        if not mapping_result["techniques"]:
            return "No data to visualize"
        
        # Extract tactics and count techniques per tactic
        tactic_counts = {}
        for technique in mapping_result["techniques"]:
            if "tactics" in technique:
                for tactic in technique["tactics"]:
                    if tactic not in tactic_counts:
                        tactic_counts[tactic] = 0
                    tactic_counts[tactic] += 1
        
        # Create DataFrame for visualization
        df = pd.DataFrame(list(tactic_counts.items()), columns=['Tactic', 'Count'])
        
        # Create bar chart
        plt.figure(figsize=(12, 8))
        sns.barplot(x='Count', y='Tactic', data=df)
        plt.title(f"ATT&CK Tactics Used by {mapping_result['malware_name']}")
        plt.tight_layout()
        plt.savefig(output_file)
        
        return f"Visualization saved to {output_file}"
    
    def generate_red_team_playbook(self, mapping_result: Dict[str, Any]) -> str:
        """Generate a red team playbook based on the identified techniques."""
        malware_name = mapping_result["malware_name"]
        techniques = mapping_result["techniques"]
        
        playbook = f"# Red Team Playbook: Simulating {malware_name} Behaviors\n\n"
        playbook += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        playbook += "This playbook provides step-by-step guidance to simulate the techniques used "
        playbook += f"by {malware_name} for red team exercises and security testing.\n\n"
        
        # Organize techniques by tactic
        tactics_to_techniques = {}
        for technique in techniques:
            if "tactics" in technique:
                for tactic in technique["tactics"]:
                    if tactic not in tactics_to_techniques:
                        tactics_to_techniques[tactic] = []
                    tactics_to_techniques[tactic].append(technique)
        
        # MITRE ATT&CK tactics in typical order of execution
        tactic_order = [
            "Reconnaissance", 
            "Resource Development",
            "Initial Access", 
            "Execution", 
            "Persistence", 
            "Privilege Escalation",
            "Defense Evasion", 
            "Credential Access", 
            "Discovery", 
            "Lateral Movement",
            "Collection", 
            "Command and Control", 
            "Exfiltration", 
            "Impact"
        ]
        
        # Common tools and commands for each technique
        technique_tools = {
            # Initial Access
            "Phishing": "Gophish, SET (Social Engineering Toolkit)",
            "Valid Accounts": "Empire, Metasploit",
            
            # Execution
            "Command and Scripting Interpreter": "PowerShell, Bash scripts, Python scripts",
            "Native API": "Windows API calls, PowerShell",
            
            # Persistence
            "Registry Run Keys / Startup Folder": "reg.exe, PowerShell",
            "Scheduled Task": "schtasks.exe, at.exe",
            
            # Privilege Escalation
            "Process Injection": "Mimikatz, PowerSploit",
            "Access Token Manipulation": "Incognito, Cobalt Strike",
            
            # Defense Evasion
            "Obfuscated Files or Information": "Veil, Shellter",
            "Indicator Removal on Host": "Clear event logs, PowerShell",
            
            # Credential Access
            "Credential Dumping": "Mimikatz, LaZagne",
            "Brute Force": "Hydra, Medusa",
            
            # Discovery
            "Network Service Scanning": "Nmap, Angry IP Scanner",
            "System Network Configuration Discovery": "ipconfig, ifconfig",
            
            # Lateral Movement
            "Remote Services": "PsExec, WMI",
            "Pass the Hash": "Mimikatz, Impacket",
            
            # Collection
            "Data from Local System": "PowerShell scripts, batch files",
            "Screen Capture": "Custom scripts",
            
            # Command and Control
            "Application Layer Protocol": "Empire, Covenant",
            "Encrypted Channel": "Meterpreter, Cobalt Strike",
            
            # Exfiltration
            "Exfiltration Over C2 Channel": "Covenant, Empire",
            "Data Compressed": "7zip, PowerShell",
            
            # Impact
            "Data Encrypted for Impact": "Custom ransomware simulation",
            "Service Stop": "sc.exe, PowerShell"
        }
        
        # Generate playbook steps
        step_number = 1
        for tactic in tactic_order:
            if tactic in tactics_to_techniques:
                playbook += f"## {tactic}\n\n"
                
                for technique in tactics_to_techniques[tactic]:
                    playbook += f"### Step {step_number}: {technique['name']} ({technique['id']})\n\n"
                    playbook += f"**Objective**: Simulate {technique['name']} technique.\n\n"
                    
                    # Add brief description
                    playbook += f"**Description**: {technique['description'][:200]}...\n\n"
                    
                    # Add suggested tools
                    for tool_technique, tools in technique_tools.items():
                        if tool_technique.lower() in technique['name'].lower():
                            playbook += f"**Suggested Tools**: {tools}\n\n"
                            break
                    else:
                        playbook += "**Suggested Tools**: Custom scripts or commands\n\n"
                    
                    # Add generic execution steps
                    playbook += "**Execution Steps**:\n"
                    playbook += "1. Prepare the environment\n"
                    playbook += "2. Execute the technique with appropriate tools\n"
                    playbook += "3. Document indicators and artifacts generated\n"
                    playbook += "4. Clean up traces (unless persistence is part of the test)\n\n"
                    
                    # Add detection methods
                    playbook += "**Detection Methods**:\n"
                    playbook += "* Monitor for unusual process executions\n"
                    playbook += "* Check for suspicious log entries\n"
                    playbook += "* Look for unexpected network connections\n\n"
                    
                    step_number += 1
        
        playbook += "## Clean-up and Reporting\n\n"
        playbook += "After completing the simulation:\n\n"
        playbook += "1. Remove all persistence mechanisms\n"
        playbook += "2. Restore any modified systems to their original state\n"
        playbook += "3. Document all findings, including:\n"
        playbook += "   * Successful technique executions\n"
        playbook += "   * Detection gaps identified\n"
        playbook += "   * Recommended security improvements\n\n"
        
        playbook += "## Disclaimer\n\n"
        playbook += "This playbook is for authorized security testing only. Ensure proper approvals "
        playbook += "are in place before conducting any red team activities.\n"
        
        return playbook


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Threat Mapper")
    parser.add_argument("--malware", "-m", required=True, help="Name of malware to map")
    parser.add_argument("--output", "-o", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--visualize", "-v", action="store_true", help="Create visualization")
    parser.add_argument("--playbook", "-p", action="store_true", help="Generate red team playbook")
    
    args = parser.parse_args()
    
    threat_mapper = ThreatMapper()
    
    print(f"\nMapping {args.malware} to MITRE ATT&CK framework...\n")
    mapping_result = threat_mapper.map_malware_to_techniques(args.malware)
    
    if not mapping_result["matched_software"]:
        print(f"No matches found for '{args.malware}' in the MITRE ATT&CK database.")
        return
    
    # Generate and output report
    report = threat_mapper.generate_report(mapping_result, args.output)
    if args.output == "text":
        print(report)
    else:
        output_file = f"{args.malware.replace(' ', '_').lower()}_report.json"
        with open(output_file, "w") as f:
            f.write(report)
        print(f"JSON report saved to {output_file}")
    
    # Create visualization if requested
    if args.visualize:
        viz_file = f"{args.malware.replace(' ', '_').lower()}_visualization.png"
        result = threat_mapper.visualize_techniques(mapping_result, viz_file)
        print(result)
    
    # Generate red team playbook if requested
    if args.playbook:
        playbook = threat_mapper.generate_red_team_playbook(mapping_result)
        playbook_file = f"{args.malware.replace(' ', '_').lower()}_playbook.md"
        with open(playbook_file, "w") as f:
            f.write(playbook)
        print(f"Red team playbook saved to {playbook_file}")


if __name__ == "__main__":
    main()