import os
import time
import json
import uuid
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, BinaryIO
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS
from dotenv import load_dotenv
import requests
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scan_service.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
# API Keys
VIRUSTOTAL_API_KEY = "e07db684f069ba9db249361ceb5f931f24af9f64ba1eab330bc84bba7f1243fd"
MALWAREBAZAAR_API_KEY = "ce5db56109631d8c0824c6f28918b38edea742fa1fc679aa"
CACHE_EXPIRY = 3600  # 1 hour

# Log API key status (without exposing the actual keys)
logger.info("VirusTotal API key is " + ("configured" if VIRUSTOTAL_API_KEY else "NOT configured"))
logger.info("MalwareBazaar API key is " + ("configured" if MALWAREBAZAAR_API_KEY else "NOT configured"))

# Simple in-memory cache
result_cache = {}

def determine_hash_type(hash_value: str) -> str:
    """Determine the type of hash (MD5, SHA-1, or SHA-256)."""
    hash_length = len(hash_value)
    if hash_length == 32:
        return 'md5'
    elif hash_length == 40:
        return 'sha1'
    elif hash_length == 64:
        return 'sha256'
    return 'unknown'

@dataclass
class ScanResult:
    """Class to hold scan results from different services."""
    service: str = "unknown"
    status: str = "not_available"
    threat_level: str = "unknown"
    detection_ratio: str = "0/0"
    detections: List[Dict[str, Any]] = None
    raw_data: Dict = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary, excluding raw_data by default."""
        result = asdict(self)
        if 'raw_data' in result:
            del result['raw_data']
        return result

def scan_with_virustotal(hash_value: str) -> Dict:
    """
    Scan a hash using VirusTotal API.
    
    Args:
        hash_value (str): The hash to scan
        
    Returns:
        dict: Standardized scan result
    """
    result = ScanResult(service="virustotal")
    
    if not VIRUSTOTAL_API_KEY:
        result.status = "error"
        result.error = "VirusTotal API key not configured"
        return result.to_dict()
    
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    
    try:
        # Log the request
        logger.info(f"Sending request to VirusTotal API for hash: {hash_value}")
        
        # Make the API request with timeout
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        vt_data = response.json()
        
        # Log the response status
        logger.debug(f"VirusTotal API response: {json.dumps(vt_data, indent=2)}")
        
        result.raw_data = vt_data
        result.status = "completed"
        
        if 'data' not in vt_data or 'attributes' not in vt_data['data']:
            logger.error(f"Unexpected VirusTotal response format: {vt_data}")
            result.status = "error"
            result.error = "Unexpected response format from VirusTotal"
            return result.to_dict()
        
        attrs = vt_data['data'].get('attributes', {})
        
        # Extract basic file information
        file_info = {
            'type': attrs.get('type_description', 'Unknown'),
            'size': attrs.get('size'),
            'first_submission_date': datetime.utcfromtimestamp(attrs.get('first_submission_date', 0)).isoformat() if attrs.get('first_submission_date') else None,
            'last_analysis_date': datetime.utcfromtimestamp(attrs.get('last_analysis_date', 0)).isoformat() if attrs.get('last_analysis_date') else None,
            'reputation': attrs.get('reputation'),
            'type_extension': attrs.get('type_extension'),
            'type_tag': attrs.get('type_tag'),
            'meaningful_name': attrs.get('meaningful_name'),
            'magic': attrs.get('magic'),
            'trid': attrs.get('trid')
        }
        
        # Set threat level and detection ratio
        if 'last_analysis_stats' in attrs:
            stats = attrs['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            result.detection_ratio = f"{malicious}/{total}"
            if malicious > 0:
                result.threat_level = "malicious"
                
                # Calculate detection percentage
                detection_percent = (malicious / total) * 100 if total > 0 else 0
                
                # Set threat level based on detection percentage
                if detection_percent >= 50:
                    result.threat_level = "high"
                elif detection_percent >= 20:
                    result.threat_level = "medium"
                else:
                    result.threat_level = "low"
            
            # Add detection details from all vendors
            if 'last_analysis_results' in attrs:
                detections = []
                for vendor, details in attrs['last_analysis_results'].items():
                    if details['category'] != 'undetected':
                        detection = {
                            'vendor': vendor,
                            'result': details.get('result', 'Malicious'),
                            'category': details.get('category', 'suspicious'),
                            'method': details.get('method', 'blacklist'),
                            'engine_version': details.get('engine_version')
                        }
                        detections.append(detection)
                
                if detections:
                    result.detections = detections
        
        # Add additional file information
        if not result.detections:
            result.detections = []
        
        # Add file information as a detection entry
        result.detections.append({
            'vendor': 'VirusTotal',
            'result': 'File Information',
            'details': file_info
        })
        
        # Add threat intelligence if available
        if 'popular_threat_classification' in attrs:
            threat_info = attrs['popular_threat_classification']
            result.detections.append({
                'vendor': 'VirusTotal',
                'result': 'Threat Intelligence',
                'details': threat_info
            })
        
        return result.to_dict()
        
    except requests.exceptions.Timeout:
        error_msg = "VirusTotal API request timed out after 15 seconds"
        logger.error(error_msg)
        result.status = "error"
        result.error = error_msg
        return result.to_dict()
        
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 404:
            error_msg = "Hash not found in VirusTotal database"
            result.status = "completed"
            result.threat_level = "clean"
            result.detection_ratio = "0/0"
        elif status_code == 401:
            error_msg = "Invalid VirusTotal API key"
            result.status = "error"
        elif status_code == 429:
            error_msg = "VirusTotal API rate limit exceeded"
            result.status = "error"
        else:
            error_msg = f"VirusTotal API HTTP error: {str(e)}"
            result.status = "error"
        
        logger.error(f"{error_msg} (Status code: {status_code})")
        result.error = error_msg
        return result.to_dict()
        
    except requests.exceptions.RequestException as e:
        error_msg = f"VirusTotal API request failed: {str(e)}"
        logger.error(error_msg)
        result.status = "error"
        result.error = error_msg
        return result.to_dict()

def scan_with_malwarebazaar(hash_value: str) -> Dict:
    """
    Scan a hash using MalwareBazaar API.
    
    Args:
        hash_value (str): The hash to scan (MD5, SHA1, or SHA256)
        
    Returns:
        dict: Standardized scan result
    """
    result = ScanResult(service="MalwareBazaar")
    
    if not MALWAREBAZAAR_API_KEY:
        result.error = "MalwareBazaar API key not configured"
        return asdict(result)
        
    # Check cache first
    cache_key = f"mb_{hash_value}"
    if cache_key in result_cache:
        cached_data = result_cache[cache_key]
        if time.time() - cached_data['timestamp'] < CACHE_EXPIRY:
            logger.info(f"Returning cached MalwareBazaar result for {hash_value}")
            return cached_data['data']
    
    url = "https://mb-api.abuse.ch/api/v1/"
    
    try:
        # Prepare the request data according to MalwareBazaar API docs
        data = {
            'query': 'get_info',
            'hash': hash_value.lower()
        }
        
        # Add the API key in the headers as per documentation
        headers = {
            'API-KEY': MALWAREBAZAAR_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Make the POST request with a timeout
        response = requests.post(
            url, 
            data=data,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        result_data = response.json()
        
        # Log the full response for debugging
        logger.info(f"MalwareBazaar response: {json.dumps(result_data, indent=2)}")
        
        # Check if the query was successful
        query_status = result_data.get('query_status')
        
        # If hash not found, return clean result
        if query_status == 'hash_not_found':
            result.status = "completed"
            result.threat_level = "clean"
            result.detection_ratio = "0/1"
            return asdict(result)
            
        # If there was an error with the query
        if query_status != 'ok':
            result.status = "error"
            result.error = f"MalwareBazaar API error: {query_status}"
            return asdict(result)
        
        # Check if we have data
        if not result_data.get('data') or not isinstance(result_data['data'], list) or len(result_data['data']) == 0:
            result.status = "completed"
            result.threat_level = "clean"
            result.detection_ratio = "0/1"
            return asdict(result)
            
        # Get the first (and should be only) result
        sample = result_data['data'][0]
        
        # Set basic info
        result.status = "completed"
        
        # If we found the hash in MalwareBazaar, it's considered malicious
        result.threat_level = "malicious"
        
        # Extract detections
        detections = []
        
        # Add signature if available
        if sample.get('signature'):
            detections.append({
                'vendor': 'MalwareBazaar',
                'category': 'signature',
                'result': sample['signature']
            })
        
        # Add tags if available
        if sample.get('tags') and isinstance(sample['tags'], list):
            for tag in sample['tags']:
                detections.append({
                    'vendor': 'MalwareBazaar',
                    'category': 'tag',
                    'result': tag
                })
        
        # Add YARA rules if available
        if sample.get('yara_rules') and isinstance(sample['yara_rules'], list):
            for rule in sample['yara_rules']:
                if isinstance(rule, dict) and rule.get('rule_name'):
                    detections.append({
                        'vendor': 'MalwareBazaar',
                        'category': 'yara',
                        'result': rule['rule_name'],
                        'description': rule.get('description', '')
                    })
        
        result.detections = detections
        result.detection_ratio = f"{len(detections)}/1"  # MalwareBazaar is a single source
        
        # Add additional file info
        file_info = {}
        
        # Basic file information
        if sample.get('file_name'):
            file_info['name'] = sample['file_name']
        if sample.get('file_size'):
            file_info['size'] = sample['file_size']
        if sample.get('file_type'):
            file_info['type'] = sample['file_type']
        if sample.get('file_type_mime'):
            file_info['mime'] = sample['file_type_mime']
            
        # Timeline information
        if sample.get('first_seen'):
            file_info['first_seen'] = sample['first_seen']
        if sample.get('last_seen'):
            file_info['last_seen'] = sample['last_seen']
            
        # Hashes
        hashes = {}
        if sample.get('md5_hash'):
            hashes['md5'] = sample['md5_hash']
        if sample.get('sha1_hash'):
            hashes['sha1'] = sample['sha1_hash']
        if sample.get('sha256_hash'):
            hashes['sha256'] = sample['sha256_hash']
        if sample.get('sha3_384_hash'):
            hashes['sha3_384'] = sample['sha3_384_hash']
        if hashes:
            file_info['hashes'] = hashes
            
        # Delivery method if available
        if sample.get('delivery_method'):
            file_info['delivery_method'] = sample['delivery_method']
            
        # Add vendor intelligence if available
        vendor_intel = {}
        if sample.get('vendor_intel'):
            for vendor, data in sample['vendor_intel'].items():
                if data and isinstance(data, dict):
                    vendor_intel[vendor] = {
                        'score': data.get('score'),
                        'category': data.get('category'),
                        'result': data.get('result')
                    }
        if vendor_intel:
            file_info['vendor_intel'] = vendor_intel
            
        result.file_info = file_info
        
        # Store raw data for reference (but limit size to prevent memory issues)
        raw_data = sample.copy()
        # Remove large binary data if present
        if 'file_content' in raw_data:
            del raw_data['file_content']
        result.raw_data = raw_data
        
        # Cache the result
        result_cache[cache_key] = {
            'timestamp': time.time(),
            'data': asdict(result)
        }
        
        return asdict(result)
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error querying MalwareBazaar API: {str(e)}"
        logger.error(error_msg)
        result.status = "error"
        result.error = error_msg
        return asdict(result)
    except Exception as e:
        error_msg = f"Unexpected error in MalwareBazaar scan: {str(e)}"
        logger.error(error_msg, exc_info=True)
        result.status = "error"
        result.error = error_msg
        return asdict(result)

def scan_url_with_virustotal(url: str) -> Dict:
    """
    Scan a URL using VirusTotal API.
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Standardized scan result
    """
    if not VIRUSTOTAL_API_KEY:
        return ScanResult(
            service="virustotal",
            status="error",
            error="VirusTotal API key not configured"
        ).to_dict()

    try:
        # Check cache first
        cache_key = f"vt_url_{url}"
        if cache_key in result_cache:
            cached_data = result_cache[cache_key]
            if time.time() - cached_data['timestamp'] < CACHE_EXPIRY:
                logger.info(f"Returning cached result for URL: {url}")
                return cached_data['data']

        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # First, submit URL for scanning
        scan_url = 'https://www.virustotal.com/api/v3/urls'
        payload = f'url={url}'
        
        response = requests.post(scan_url, headers=headers, data=payload)
        response.raise_for_status()
        
        # Get the analysis ID from the response
        analysis_id = response.json()['data']['id']
        
        # Now get the analysis results
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        
        # Wait for the analysis to complete (with timeout)
        max_retries = 5
        retry_delay = 2  # seconds
        
        for _ in range(max_retries):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()
            
            if analysis_data['data']['attributes']['status'] == 'completed':
                break
                
            time.sleep(retry_delay)
        
        # Get the URL report
        url_id = analysis_data['meta']['url_info']['id']
        report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()
        report_data = report_response.json()
        
        # Process the results
        attributes = report_data['data']['attributes']
        stats = attributes['last_analysis_stats']
        total = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        # Enhanced threat level calculation
        if total == 0:
            threat_level = 'unknown'
        elif malicious + suspicious == 0:
            threat_level = 'clean'
        else:
            # Calculate detection ratio
            detection_ratio = (malicious + suspicious) / total
            
            # Set threat level based on detection ratio and absolute counts
            if malicious >= 5 or detection_ratio > 0.2:  # High confidence of maliciousness
                threat_level = 'malicious'
            elif malicious > 0 or suspicious >= 3:  # Medium confidence
                threat_level = 'suspicious'
            else:  # Low confidence
                threat_level = 'potentially_suspicious'
        
        # Format detections
        detections = []
        for engine, result in attributes['last_analysis_results'].items():
            if result['category'] in ['malicious', 'suspicious']:
                detections.append({
                    'engine': engine,
                    'category': result['category'],
                    'result': result.get('result', 'detected'),
                    'method': result.get('method', 'unknown')
                })
        
        result = ScanResult(
            service="virustotal",
            status="completed",
            threat_level=threat_level,
            detection_ratio=f"{malicious}/{total}",
            detections=detections,
            raw_data=report_data
        ).to_dict()
        
        # Cache the result
        result_cache[cache_key] = {
            'timestamp': time.time(),
            'data': result
        }
        
        return result
        
    except Exception as e:
        error_msg = f"Error scanning URL with VirusTotal: {str(e)}"
        logger.error(error_msg)
        return ScanResult(
            service="virustotal",
            status="error",
            error=error_msg
        ).to_dict()

def scan_url_with_urlhaus(url: str) -> Dict:
    """
    Check a URL against URLHaus database.
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Standardized scan result
    """
    try:
        # Check cache first
        cache_key = f"urlhaus_{url}"
        if cache_key in result_cache:
            cached_data = result_cache[cache_key]
            if time.time() - cached_data['timestamp'] < CACHE_EXPIRY:
                logger.info(f"Returning cached URLHaus result for URL: {url}")
                return cached_data['data']
        
        # URLHaus API endpoint for URL check
        api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
        
        # Prepare the payload
        data = {
            'url': url
        }
        
        # Make the request
        response = requests.post(api_url, data=data)
        response.raise_for_status()
        result = response.json()
        
        # Process the response
        if 'query_status' in result and result['query_status'] == 'no_results':
            return ScanResult(
                service="urlhaus",
                status="completed",
                threat_level="clean",
                detection_ratio="0/0",
                detections=[],
                raw_data=result
            ).to_dict()
            
        # If we get here, the URL was found in URLHaus
        detections = [{
            'engine': 'URLHaus',
            'category': 'malicious',
            'result': result.get('threat', 'Malicious URL'),
            'url_status': result.get('url_status', 'unknown'),
            'date_added': result.get('date_added', '')
        }]
        
        result_data = ScanResult(
            service="urlhaus",
            status="completed",
            threat_level="malicious",
            detection_ratio=f"1/1",  # URLHaus only reports if it's malicious
            detections=detections,
            raw_data=result
        ).to_dict()
        
        # Cache the result
        result_cache[cache_key] = {
            'timestamp': time.time(),
            'data': result_data
        }
        
        return result_data
        
    except Exception as e:
        error_msg = f"Error checking URL with URLHaus: {str(e)}"
        logger.error(error_msg)
        return ScanResult(
            service="urlhaus",
            status="error",
            error=error_msg
        ).to_dict()

def combine_scan_results(*scan_results: List[Dict]) -> Dict:
    """
    Combine results from multiple scan services into a single, unified result.
    
    Args:
        *scan_results: List of scan results from different services
        
    Returns:
        dict: Combined and unified scan result
    """
    # Define threat level hierarchy for comparison
    THREAT_LEVELS = {
        'unknown': 0,
        'clean': 1,
        'potentially_suspicious': 2,
        'suspicious': 3,
        'malicious': 4
    }
    
    # Initialize combined result with default values
    combined = {
        'status': 'completed',
        'threat_level': 'unknown',
        'detection_ratio': '0/0',
        'file_info': {},
        'detections': [],
        'threat_intel': {},
        'hashes': {},
        'tags': set(),
        'first_seen': None,
        'last_seen': None,
        'scan_date': datetime.utcnow().isoformat(),
        'scan_id': str(uuid.uuid4()),
        'error': None,
        'services': [],
        'url': None,
        'scan_type': 'hash'  # Default to hash scan
    }
    
    # Initialize counters
    total_detections = 0
    total_engines = 0
    threat_levels = []
    
    # Process each service result
    for service_result in scan_results:
        if not service_result or 'status' not in service_result:
            continue
            
        # Skip if service returned an error
        if service_result.get('status') != 'completed':
            continue
            
        service_name = service_result.get('service', 'unknown')
        
        # Process detections and detection ratio
        if 'detection_ratio' in service_result:
            try:
                detections, engines = map(int, service_result['detection_ratio'].split('/'))
                total_detections += detections
                total_engines += engines
            except (ValueError, AttributeError):
                pass
        
        # Track threat level
        if 'threat_level' in service_result:
            current_level = service_result['threat_level']
            threat_levels.append(current_level)
            
            # Update combined threat level if current is more severe
            if THREAT_LEVELS.get(current_level, 0) > THREAT_LEVELS.get(combined['threat_level'], 0):
                combined['threat_level'] = current_level
                
        # Preserve URL and scan type for URL scans
        if 'url' in service_result and service_result['url']:
            combined['url'] = service_result['url']
            combined['scan_type'] = 'url'
        
        # Process detections
        if 'detections' in service_result and service_result['detections']:
            for detection in service_result['detections']:
                # Skip file information detections (we'll handle them separately)
                if detection.get('result') in ['File Information', 'Threat Intelligence']:
                    # Extract file information
                    if 'details' in detection:
                        if detection['result'] == 'File Information':
                            combined['file_info'].update(detection['details'])
                        elif detection['result'] == 'Threat Intelligence':
                            combined['threat_intel'].update(detection['details'])
                    continue
                
                # Clean up detection entry
                clean_detection = {
                    'vendor': detection.get('vendor'),
                    'result': detection.get('result'),
                    'category': detection.get('category'),
                    'details': {}
                }
                
                # Add any additional details
                for key, value in detection.items():
                    if key not in ['vendor', 'result', 'category'] and value is not None:
                        clean_detection['details'][key] = value
                
                # Add hashes if present
                if 'hashes' in detection and detection['hashes']:
                    combined['hashes'].update(detection['hashes'])
                
                # Add tags if present
                if 'tags' in detection and detection['tags']:
                    combined['tags'].update(tag.lower() for tag in detection['tags'] if tag)
                
                # Update first_seen and last_seen if available
                if 'first_seen' in detection and detection['first_seen']:
                    if not combined['first_seen'] or detection['first_seen'] < combined['first_seen']:
                        combined['first_seen'] = detection['first_seen']
                
                if 'last_seen' in detection and detection['last_seen']:
                    if not combined['last_seen'] or detection['last_seen'] > combined['last_seen']:
                        combined['last_seen'] = detection['last_seen']
                
                # Add to detections if not a duplicate
                if clean_detection not in combined['detections']:
                    combined['detections'].append(clean_detection)
    
    # Determine overall threat level
    if threat_levels:
        if 'high' in threat_levels or 'malicious' in threat_levels:
            combined['threat_level'] = 'malicious'
        elif 'medium' in threat_levels:
            combined['threat_level'] = 'suspicious'
        elif 'low' in threat_levels:
            combined['threat_level'] = 'low'
    
    # Update combined detection ratio
    if total_engines > 0:
        combined['detection_ratio'] = f"{total_detections}/{total_engines}"
    
    # Convert sets to lists for JSON serialization
    if combined['tags']:
        combined['tags'] = list(combined['tags'])
    
    # Clean up empty fields
    if not combined['detections']:
        del combined['detections']
    if not combined['threat_intel']:
        del combined['threat_intel']
    if not combined['hashes']:
        del combined['hashes']
    if not combined['tags']:
        del combined['tags']
    
    return combined

@app.route('/api/scan/hash', methods=['POST'])
def scan_hash():
    """
    API endpoint to scan a file hash.
    
    Expected JSON payload:
    {
        "hash": "<hash_value>"
    }
    
    Returns:
        JSON response with combined scan results from all services
    """
    start_time = time.time()
    
    # Log request details
    logger.info(f"Incoming request: {request.method} {request.url}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    logger.debug(f"Request data: {request.get_data()}")
    
    try:
        # Parse request data
        data = request.get_json()
        if not data or 'hash' not in data or not data['hash']:
            return jsonify({
                "status": "error",
                "message": "No hash provided"
            }), 400
            
        hash_value = data['hash'].strip()
        logger.info(f"Received scan request for hash: {hash_value}")
        
        # Check cache first
        cache_key = f"hash_{hash_value}"
        if cache_key in result_cache:
            cached_data = result_cache[cache_key]
            if time.time() - cached_data['timestamp'] < CACHE_EXPIRY:
                logger.info(f"Returning cached result for hash: {hash_value}")
                return jsonify(cached_data['data'])
        
        # Determine hash type
        hash_type = determine_hash_type(hash_value)
        if hash_type == 'unknown':
            return jsonify({
                "status": "error",
                "message": "Invalid hash format. Must be MD5, SHA-1, or SHA-256."
            }), 400
        
        # Initialize base result structure
        base_result = {
            'scan_id': f'scan_{int(time.time())}_{hash_value[:8]}',
            'hash': hash_value,
            'hash_type': hash_type,
            'scan_date': datetime.utcnow().isoformat(),
            'tags': []
        }
        
        # Run scans in parallel (using threads for simplicity)
        import threading
        
        vt_result = {'service': 'virustotal'}
        mb_result = {'service': 'malwarebazaar'}
        
        def run_vt_scan():
            nonlocal vt_result
            logger.info(f"Starting VirusTotal scan for hash: {hash_value}")
            try:
                vt_result.update(scan_with_virustotal(hash_value))
                logger.info(f"VirusTotal scan completed for {hash_value}")
            except Exception as e:
                logger.error(f"Error in VirusTotal scan: {str(e)}", exc_info=True)
                vt_result.update({
                    'status': 'error',
                    'error': f'VirusTotal scan failed: {str(e)}'
                })
            
        def run_mb_scan():
            nonlocal mb_result
            if MALWAREBAZAAR_API_KEY:
                logger.info(f"Starting MalwareBazaar scan for hash: {hash_value}")
                try:
                    mb_result.update(scan_with_malwarebazaar(hash_value))
                    logger.info(f"MalwareBazaar scan completed for {hash_value}")
                except Exception as e:
                    logger.error(f"Error in MalwareBazaar scan: {str(e)}", exc_info=True)
                    mb_result.update({
                        'status': 'error',
                        'error': f'MalwareBazaar scan failed: {str(e)}'
                    })
            else:
                logger.warning("Skipping MalwareBazaar scan - API key not configured")
                mb_result.update({
                    'status': 'not_available',
                    'error': 'MalwareBazaar API key not configured'
                })
        
        # Start scan threads
        vt_thread = threading.Thread(target=run_vt_scan)
        mb_thread = threading.Thread(target=run_mb_scan)
        
        vt_thread.start()
        mb_thread.start()
        
        # Wait for all threads to complete with timeout
        vt_thread.join(timeout=10)
        mb_thread.join(timeout=10)
        
        # Combine results
        combined_result = combine_scan_results(vt_result, mb_result)
        
        # Merge with base result
        final_result = {**base_result, **combined_result}
        
        # Cache the result
        result_cache[cache_key] = {
            'timestamp': time.time(),
            'data': final_result
        }
        
        # Log performance
        duration = time.time() - start_time
        logger.info(f"Completed scan for {hash_value} in {duration:.2f} seconds")
        
        return jsonify(final_result)
        
    except Exception as e:
        logger.error(f"Error in scan_hash: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}',
            'service': 'scan_service'
        }), 500

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """
    API endpoint to scan a URL.
    
    Expected JSON payload:
    {
        "url": "<url_to_scan>"
    }
    
    Returns:
        JSON response with combined scan results from all URL scanning services
    """
    try:
        # Get the JSON data from the request
        data = request.get_json()
        
        # Validate the request
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameter: url'
            }), 400
            
        url_value = data['url'].strip()
        
        # Basic URL validation
        if not (url_value.startswith('http://') or url_value.startswith('https://')):
            url_value = 'http://' + url_value
            
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url_value)
            if not parsed_url.netloc:  # No domain name
                raise ValueError("Invalid URL")
        except Exception:
            return jsonify({
                'status': 'error',
                'message': 'Invalid URL format. Please include http:// or https:// and a valid domain.'
            }), 400
            
        logger.info(f"Received URL scan request for: {url_value}")
        
        # Check cache first
        cache_key = f"url_{url_value}"
        if cache_key in result_cache:
            cached_data = result_cache[cache_key]
            if time.time() - cached_data['timestamp'] < CACHE_EXPIRY:
                logger.info(f"Returning cached result for URL: {url_value}")
                return jsonify(cached_data['data'])
        
        # Start scanning with all available URL scanning services
        scan_results = []
        
        # Scan with VirusTotal if API key is configured
        if VIRUSTOTAL_API_KEY:
            logger.info(f"Scanning URL with VirusTotal: {url_value}")
            vt_result = scan_url_with_virustotal(url_value)
            scan_results.append(vt_result)
        else:
            logger.warning("VirusTotal API key not configured, skipping URL scan")
        
        # Check with URLHaus
        logger.info(f"Checking URL with URLHaus: {url_value}")
        urlhaus_result = scan_url_with_urlhaus(url_value)
        scan_results.append(urlhaus_result)
        
        # Combine results from all services
        combined_results = combine_scan_results(*scan_results)
        
        # Add URL-specific fields
        combined_results['url'] = url_value
        combined_results['scan_type'] = 'url'
        
        # Cache the results
        result_cache[cache_key] = {
            'timestamp': time.time(),
            'data': combined_results
        }
        
        logger.info(f"Completed URL scan for {url_value}. Status: {combined_results.get('status')}")
        
        return jsonify(combined_results)
        
    except Exception as e:
        error_msg = f"Error processing URL scan request: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            'status': 'error',
            'message': error_msg
        }), 500

def calculate_file_hash(file_stream: BinaryIO) -> Dict[str, str]:
    """
    Calculate MD5, SHA-1, and SHA-256 hashes of a file.
    
    Args:
        file_stream: File-like object to calculate hashes for
        
    Returns:
        dict: Dictionary containing the different hash types and their values
    """
    # Initialize hash objects
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    # Read the file in chunks to handle large files
    chunk_size = 65536  # 64KB chunks
    
    # Reset file pointer to the beginning
    file_stream.seek(0)
    
    # Read and update hash objects in chunks
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)
    
    # Return the hexadecimal digest of each hash
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """
    API endpoint to scan an uploaded file.
    
    Expected form data:
    - file: The file to scan (multipart/form-data)
    
    Returns:
        JSON response with combined scan results from all services
    """
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file part in the request'
            }), 400
            
        file = request.files['file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No selected file'
            }), 400
            
        if file:
            # Secure the filename
            filename = secure_filename(file.filename)
            logger.info(f"Processing file upload: {filename}")
            
            # Calculate file hashes
            file_hashes = calculate_file_hash(file.stream)
            
            # Start scanning with all available services
            scan_results = []
            
            # Get the SHA-256 hash for scanning (preferred by most services)
            sha256_hash = file_hashes['sha256']
            
            # Scan with VirusTotal if API key is configured
            if VIRUSTOTAL_API_KEY:
                logger.info(f"Scanning file hash with VirusTotal: {sha256_hash}")
                vt_result = scan_with_virustotal(sha256_hash)
                scan_results.append(vt_result)
            else:
                logger.warning("VirusTotal API key not configured, skipping file scan")
            
            # Scan with MalwareBazaar if API key is configured
            if MALWAREBAZAAR_API_KEY:
                logger.info(f"Scanning file hash with MalwareBazaar: {sha256_hash}")
                mb_result = scan_with_malwarebazaar(sha256_hash)
                scan_results.append(mb_result)
            else:
                logger.warning("MalwareBazaar API key not configured, skipping file scan")
            
            # Combine results from all services
            combined_results = combine_scan_results(*scan_results)
            
            # Add file-specific fields
            combined_results['filename'] = filename
            combined_results['file_size'] = file.content_length
            combined_results['hashes'] = file_hashes
            combined_results['scan_type'] = 'file'
            
            # Cache the results
            cache_key = f"file_{sha256_hash}"
            result_cache[cache_key] = {
                'timestamp': time.time(),
                'data': combined_results
            }
            
            logger.info(f"Completed file scan for {filename}. Status: {combined_results.get('status')}")
            
            return jsonify(combined_results)
            
    except Exception as e:
        error_msg = f"Error processing file upload: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            'status': 'error',
            'message': error_msg
        }), 500

@app.route('/api/status', methods=['GET'])
def status_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "message": "Scan service is running",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "features": ["hash_scan", "url_scan", "file_scan"]
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    logger.info(f"Starting scan service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
