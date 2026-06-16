import os
from dotenv import load_dotenv
import requests

def check_environment():
    # Load environment variables
    load_dotenv(override=True)
    
    # Get API keys
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    mb_key = os.getenv("MALWARE_BAZAAR_API_KEY")
    
    print("Environment Check:")
    print(f"VIRUSTOTAL_API_KEY: {'***' + vt_key[-4:] if vt_key else 'Not set'}")
    print(f"MALWARE_BAZAAR_API_KEY: {'***' + mb_key[-4:] if mb_key else 'Not set'}")
    print()
    
    return vt_key, mb_key

def test_virustotal(api_key):
    print("Testing VirusTotal API...")
    url = "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"  # Test endpoint
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("✓ VirusTotal API connection successful!")
            return True
        else:
            print(f"✗ VirusTotal API error: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"✗ Error connecting to VirusTotal: {str(e)}")
        return False

def test_malwarebazaar(api_key):
    print("\nTesting MalwareBazaar API...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        'query': 'get_info',
        'hash': '1317354d4079fb6b282d1bba6344e48ca9ffa257d97972bef072833d898ac6e5',
    }
    
    try:
        response = requests.post(url, data=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('query_status') == 'ok':
                print("✓ MalwareBazaar API connection successful!")
                return True
            else:
                print(f"✗ MalwareBazaar API error: {result.get('query_status')}")
                return False
        else:
            print(f"✗ MalwareBazaar API error: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"✗ Error connecting to MalwareBazaar: {str(e)}")
        return False

if __name__ == "__main__":
    vt_key, mb_key = check_environment()
    
    if vt_key:
        test_virustotal(vt_key)
    else:
        print("Skipping VirusTotal test - no API key found")
    
    if mb_key:
        test_malwarebazaar(mb_key)
    else:
        print("Skipping MalwareBazaar test - no API key found")
