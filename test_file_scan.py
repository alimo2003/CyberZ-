import os
import sys
import hashlib
import requests
from pathlib import Path

def calculate_file_hashes(file_path):
    """Calculate MD5, SHA-1, and SHA-256 hashes of a file."""
    # Initialize hash objects
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    # Read file in chunks to handle large files
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(8192)  # 8KB chunks
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

def test_file_scan(file_path):
    """Test the file scanning functionality."""
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return
        
    # Calculate file hashes
    print("\n=== Calculating file hashes ===")
    hashes = calculate_file_hashes(file_path)
    print(f"File: {os.path.basename(file_path)}")
    print(f"Size: {os.path.getsize(file_path)} bytes")
    print(f"MD5:    {hashes['md5']}")
    print(f"SHA-1:  {hashes['sha1']}")
    print(f"SHA-256: {hashes['sha256']}")
    
    # Prepare the file for upload
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    
    # Send the file for scanning
    print("\n=== Sending file for scanning ===")
    try:
        response = requests.post(
            'http://localhost:8000/api/scan/file',
            files=files
        )
        response.raise_for_status()
        result = response.json()
        
        # Print the results
        print("\n=== Scan Results ===")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Threat Level: {result.get('threat_level', 'unknown')}")
        print(f"Detection Ratio: {result.get('detection_ratio', 'N/A')}")
        
        if 'file_info' in result and result['file_info']:
            print("\nFile Information:")
            for key, value in result['file_info'].items():
                print(f"  {key}: {value}")
                
        if 'detections' in result and result['detections']:
            print("\nDetections:")
            for i, detection in enumerate(result['detections'], 1):
                print(f"  {i}. {detection.get('vendor')} - {detection.get('result')} ({detection.get('category')})")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"\nError during scan: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
    finally:
        # Make sure to close the file
        files['file'][1].close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_file_scan.py <path_to_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    test_file_scan(file_path)
