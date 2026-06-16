# Scanning Service

A FastAPI-based microservice for scanning URLs, files, IPs, and hashes using VirusTotal and abuse.ch services. This service integrates with the React frontend to provide comprehensive security scanning capabilities.

## Features

- Scan URLs for malicious content
- Analyze files by hash or file upload
- Check IP reputation
- Cache scan results for improved performance
- RESTful API with OpenAPI documentation
- SQL Server database integration for storing scan results

- Health check endpoint to verify API connectivity

## Setup

1. Clone the repository
2. Install dependencies:
   ```
   pip install fastapi uvicorn python-dotenv requests python-magic pyodbc
   ```
3. Create a `.env` file with your API keys and configuration:
   ```
   # VirusTotal API Key (required)
   # Get your API key from https://www.virustotal.com/gui/my-apikey
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   
   # MalwareBazaar API Key (optional)
   # MALWARE_BAZAAR_API_KEY=your_malwarebazaar_api_key_here
   
   # ThreatFox API Key (optional)
   # THREAT_FOX_API_KEY=your_threatfox_api_key_here
   
   # Database configuration
   DB_SERVER=localhost\SQLEXPRESS
   DB_NAME=CyberZ
   # SQL Server Authentication (comment out if using Windows Authentication)
   # DB_USER=your_username
   # DB_PASSWORD=your_password
   
   # Server settings
   HOST=0.0.0.0
   PORT=8000
   DEBUG=True
   
   # API Base URL for the frontend to use
   VIRUSTOTAL_URL=https://www.virustotal.com/api/v3
   ```

4. Make sure you have SQL Server installed and configured. The service uses Windows Authentication by default, but you can configure SQL Server Authentication by uncommenting and setting the DB_USER and DB_PASSWORD variables in the .env file.

5. Run the service:
   ```
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

## API Endpoints

### Health Check
- `GET /health` - Check API health and VirusTotal API key validity

### Scanning
- `POST /scan` - Scan a URL, IP, or hash
- `POST /scan/file` - Scan a file

### Results Retrieval
- `GET /scans/recent` - Get recent scan results
- `GET /scans/by-type/{scan_type}` - Get scan results by type (url, ip, hash, file)
- `GET /scans/{scan_id}` - Get detailed scan results by ID



## Integration with React Frontend

The scanning service is designed to work with the React frontend component `VirusTotalIntegration.jsx`. The frontend makes API calls to this service to perform scans and retrieve results.

### Frontend Integration Points

1. **API Health Check**: The frontend checks the API status on component mount using the `/health` endpoint.

2. **Scanning**: The frontend sends scan requests to the `/scan` or `/scan/file` endpoints based on the type of scan (URL, IP, hash, or file).



4. **Scan History**: The frontend retrieves scan history using the `/scans/recent` and `/scans/by-type/{scan_type}` endpoints.

### CORS Configuration

The scanning service has CORS middleware enabled to allow requests from the React frontend. By default, it allows requests from any origin in development mode.

## Database Schema

The service uses a SQL Server database with the following tables:

- `scans` - Stores metadata about each scan (ID, type, target, timestamp)
- `scan_results` - Stores detailed scan results (scan ID, raw results, formatted results)

## Error Handling

The service includes comprehensive error handling for:

- Invalid API keys
- Network connectivity issues
- Rate limiting by VirusTotal
- Database connection failures
- Invalid input formats

## Future Enhancements

- Asynchronous scanning for large files
- Webhook notifications for scan completion
- Integration with additional threat intelligence services
- Advanced result filtering and search capabilities
   ```
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

## Running the Service

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## API Endpoints

- `GET /`: Service status
- `POST /scan`: Generic scan endpoint
- `POST /scan/file`: Upload and scan a file

## Database Schema

The service uses SQLite with the following schema:

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_type, target)
);
```

## Environment Variables

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key
- `MALWARE_BAZAAR_API_KEY`: Your MalwareBazaar API key (optional)
- `THREAT_FOX_API_KEY`: Your ThreatFox API key (optional)

## Development

1. Install development dependencies:
   ```
   pip install -r requirements-dev.txt
   ```
2. Run tests:
   ```
   pytest
   ```

## License

MIT
