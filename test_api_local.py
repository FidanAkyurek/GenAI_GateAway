import urllib.request
import json
import traceback

def test_api():
    # We need a super_admin token. To get one, we can call login.
    login_data = json.dumps({"username": "superadmin", "password": "superadmin123"}).encode('utf-8')
    req = urllib.request.Request('http://127.0.0.1:8001/api/v1/auth/login', data=login_data, headers={'Content-Type': 'application/json'})
    try:
        res = urllib.request.urlopen(req)
        token_data = json.loads(res.read().decode('utf-8'))
        token = token_data['access_token']
        print("Logged in, token acquired.")
        
        # Now fetch company details
        req_details = urllib.request.Request('http://127.0.0.1:8001/api/v1/admin/super/company-details/1', headers={'Authorization': 'Bearer ' + token})
        res_details = urllib.request.urlopen(req_details)
        print("Company details:")
        print(res_details.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"HTTPError: {e.code}")
        print(e.read().decode('utf-8'))
    except Exception as e:
        print("Error:")
        traceback.print_exc()

if __name__ == "__main__":
    test_api()
