# Threat Intelligence Extractor

## Overview
This project extracts threat intelligence from structured and unstructured reports, including PDFs and text files. The tool identifies various Indicators of Compromise (IOCs), Tactics, Techniques, and Procedures (TTPs), threat actors, malware, and targeted entities using regular expressions, natural language processing (NLP), and API calls.

## Features
- Extracts **Indicators of Compromise (IOCs)** such as IP addresses, domains, emails, and file hashes.
- Identifies **Tactics, Techniques, and Procedures (TTPs)** using the Llama API.
- Detects **threat actors** mentioned in the report.
- Extracts **malware names** and enriches them with VirusTotal lookup.
- Identifies **targeted entities** like organizations and locations.
- Supports PDF, TXT, and LOG file formats.

## Prerequisites
Make sure you have the following installed:
- Python 3.7+
- Required dependencies:
  ```bash
  pip install requests spacy pdfminer.six
  python -m spacy download en_core_web_sm
  ```
- API keys for **Llama API** and **VirusTotal**

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/its-ryan/threat-intelligence-extractor.git
   cd threat-intelligence-extractor
   ```

2. Modify the script to include your API keys:
   ```python
   llamaApiKey = "YOUR_LLAMA_API_KEY"
   vtApiKey = "YOUR_VIRUSTOTAL_API_KEY"
   ```

3. Run the script:
   ```bash
   python threat_intelligence_extractor.py
   ```
   Enter the path to a PDF, TXT, or LOG file when prompted.

## Output
The script outputs extracted threat intelligence in JSON format:
```json
{
    "Iocs": {
        "IPAddresses": ["192.168.1.1"],
        "Domains": ["malicious.com"],
        "Emails": ["attacker@evil.com"],
        "FileHashes": ["5d41402abc4b2a76b9719d911017c592"]
    },
    "Ttps": {"TTPs": ["Phishing", "Command and Control"]},
    "ThreatActor(s)": ["APT29"],
    "Malware": [{"Name": "TrickBot", "md5": "abcd1234", "sha256": "xyz987"}],
    "TargetedEntities": ["Government Agency"]
}
```

## Error Handling
- If an API request fails, appropriate error messages are displayed.
- If no text is extracted, the program prompts the user accordingly.
- JSON decoding errors are handled gracefully.


## License
This project is licensed under the MIT License.


