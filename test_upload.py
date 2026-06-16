import requests

def test_file_upload():
    url = "http://localhost:8000/api/scan/file"
    file_path = r"f:\\Graduation Project\\test_file.txt"
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': ('test_file.txt', f, 'text/plain')}
            response = requests.post(url, files=files)
            
        print(f"Status Code: {response.status_code}")
        print("Response:")
        print(response.json())
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_file_upload()
