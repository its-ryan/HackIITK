import re
import requests
import json
import spacy
from pdfminer.high_level import extract_text

nlp = spacy.load("en_core_web_sm")
llamaApiKey = "LLAMA_API_KEY"
llamaApiUrl = "https://api.groq.com/openai/v1/chat/completions"

def llamaApiQuery(prompt):
    headers = {
        "Authorization": f"Bearer {llamaApiKey}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500
    }
    try:
        response = requests.post(llamaApiUrl, headers=headers, data=json.dumps(payload))
        response.raiseForStatus()
        content = response.json().get('choices', [{}])[0].get('message', {}).get('content', '').strip()
        if not content:
            print("[WARNING] Empty response content from Llama API")
            return None
        return content
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed, Please try again later: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON response: {e}")
        return None

def extractIocs(reportText):
    iocs = {
        'IPAddresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', reportText),
        'Domains': re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', reportText),
        'Emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', reportText),
        'FileHashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', reportText)
    }
    return iocs

def extractTtps(reportText):
    prompt = f"Extract the Tactics, Techniques, and Procedures from this threat report: {reportText[:4000]}"
    response = llamaApiQuery(prompt)
    if not response:
        print("[ERROR] Empty or invalid response received for TTP extraction")
        return {}
    try:
        return json.loads(response)
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decoding error for TTP extraction: {e}")
        print("Response received successfully:", response)
        return {}

def extractThreatActors(reportText):
    prompt = f"Identify the threat actor groups or individuals mentioned in this report: {reportText[:4000]}"
    response = llamaApiQuery(prompt)
    if not response:
        return []
    try:
        return json.loads(response).get("ThreatActor(s)", [])
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decoding error for threat actors: {e}")
        print("Response received successfully:", response)
        return []

def extractMalware(reportText):
    prompt = f"Extract malware names mentioned in this report: {reportText[:4000]}"
    response = llamaApiQuery(prompt)
    if not response:
        return []
    try:
        malwareList = json.loads(response).get("Malware", [])
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decoding error for malware extraction: {e}")
        print("Response received successfully:", response)
        return []
    enrichedMalware = []
    for malware in malwareList:
        vtUrl = f"https://www.virustotal.com/api/v3/files/{malware}"
        headers = {"x-apikey": "x-apikey"}
        try:
            vtResponse = requests.get(vtUrl, headers=headers)
            vtResponse.raiseForStatus()
            data = vtResponse.json().get('data', {})
            enrichedMalware.append({
                'Name': malware,
                'md5': data.get('attributes', {}).get('md5', ''),
                'sha1': data.get('attributes', {}).get('sha1', ''),
                'sha256': data.get('attributes', {}).get('sha256', ''),
                'tags': data.get('attributes', {}).get('tags', [])
            })
        except requests.exceptions.RequestException:
            enrichedMalware.append({'Name': malware, 'Error': 'VirusTotal lookup failed'})
    return enrichedMalware

def extractTargetedEntities(reportText):
    doc = nlp(reportText)
    entities = [ent.text for ent in doc.ents if ent.label_ in ['ORG', 'GPE']]
    return list(set(entities))

def extractTextFromDocument(filePath):
    if filePath.endswith('.pdf'):
        try:
            return extract_text(filePath)
        except Exception as e:
            print(f"[ERROR] Error reading PDF: {e}")
            return ""
    elif filePath.endswith(('.txt', '.log')):
        try:
            with open(filePath, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            print(f"[ERROR] Error reading text file: {e}")
            return ""
    else:
        print("[ERROR] Unsupported file format. Please provide a .pdf, .txt, or .log file.")
        return ""

def extractThreatIntelligence(filePath):
    reportText = extractTextFromDocument(filePath)
    if not reportText.strip():
        print("[ERROR] No text extracted from the document.")
        return {}

    print("[INFO] Successfully extracted text from the document.")
    return {
        'Iocs': extractIocs(reportText),
        'Ttps': extractTtps(reportText),
        'ThreatActor(s)': extractThreatActors(reportText),
        'Malware': extractMalware(reportText),
        'TargetedEntities': extractTargetedEntities(reportText)
    }

filePath = input("Enter file name (PDF or text file): ")
output = extractThreatIntelligence(filePath)

if output:
    print(json.dumps(output, indent=4))
else:
    print("[INFO] No threat intelligence extracted.")
