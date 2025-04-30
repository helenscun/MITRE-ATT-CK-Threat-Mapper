# MITRE ATT&CK Threat Mapper

A Python application that leverages the MITRE ATT&CK framework to map malware samples to techniques, generate threat intelligence reports, create visualizations, and build custom red team playbooks.

## Overview

The MITRE ATT&CK Threat Mapper is a security tool designed to:

- Map detected malware to MITRE ATT&CK tactics and techniques
- Generate comprehensive threat intelligence reports
- Visualize attack patterns through heatmaps and charts
- Create customized red team playbooks based on real-world malware behaviors

This tool helps security teams understand malware behaviors in the context of the MITRE ATT&CK framework, the gold standard for adversary tactics and techniques.

## Features

- **MITRE ATT&CK API Integration**: Fetches and locally caches the latest framework data
- **Malware Mapping**: Links malware names to corresponding ATT&CK techniques
- **Threat Intelligence Reports**: Generates detailed reports in both text and JSON formats
- **Tactical Visualizations**: Creates visual representations of techniques by tactic
- **Custom Red Team Playbooks**: Automatically generates testing procedures based on identified techniques
- **Intelligent Caching**: Reduces API calls and improves performance with smart caching

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/helenscun/mitre-attack-threat-mapper.git
cd mitre-attack-threat-mapper
```

2. Create a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Map a malware sample to ATT&CK techniques:

```bash
python mitre_threat_mapper.py --malware "Emotet"
```

### Advanced Options

```bash
python mitre_threat_mapper.py --malware "Emotet" --output json --visualize --playbook
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--malware` | `-m` | Name of malware to map (required) | N/A |
| `--output` | `-o` | Output format (`text` or `json`) | `text` |
| `--visualize` | `-v` | Create visualization | False |
| `--playbook` | `-p` | Generate red team playbook | False |

### Example Output

The tool generates several files based on your options:

- `emotet_report.json` - JSON-formatted threat intelligence report
- `emotet_visualization.png` - Visualization of techniques by tactic
- `emotet_playbook.md` - Markdown red team playbook

## Sample Report

```
# Threat Intelligence Report: Emotet

Generated on: 2025-04-30 12:34:56

## Matched Malware/Software

- **Emotet** (S0367)
  Type: malware
  Description: Emotet is a modular banking Trojan that primarily functions as a downloader or dropper of other banking Trojans...

## ATT&CK Tactics Used

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration

## ATT&CK Techniques Used

- **Phishing** (T1566)
  Tactics: Initial Access
  Description: Phishing is a technique that attackers use to trick users into providing sensitive information or installing malware...

[Additional techniques listed...]

## Recommendations

Based on the identified techniques, consider implementing these mitigations:

- **Initial Access**: Implement multi-factor authentication and security awareness training.
- **Execution**: Use application whitelisting and script execution controls.
[Additional recommendations...]
```

## Architecture

The tool consists of two main classes:

1. **MitreAttackAPI**: Handles all API interactions with the MITRE ATT&CK framework
2. **ThreatMapper**: Performs the mapping logic between malware and techniques

Data is cached locally to improve performance and reduce API calls.

## Use Cases

- **Threat Intelligence Teams**: Understand malware behaviors and capabilities
- **Security Operations**: Map detected malware to known tactics and techniques
- **Red Teams**: Generate realistic attack scenarios based on real-world malware
- **Blue Teams**: Develop detection strategies for specific malware families
- **Training**: Create educational content about malware behaviors

## Extending the Tool

### Adding New Report Formats

Extend the `generate_report` method in the `ThreatMapper` class:

```python
def generate_report(self, mapping_result: Dict[str, Any], output_format: str = "text") -> str:
    # Existing code...
    
    elif output_format == "html":
        # Generate HTML report
        return html_report
```

### Adding New Visualizations

Create new visualization methods in the `ThreatMapper` class:

```python
def visualize_techniques_radar(self, mapping_result: Dict[str, Any], output_file: str = "radar.png") -> str:
    # Generate radar chart visualization
    return f"Radar visualization saved to {output_file}"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation
- This tool utilizes the MITRE ATT&CK API (https://attack.mitre.org/api/)

## Contact

For questions or feedback, please open an issue on GitHub or contact helenscun@gmail.com
