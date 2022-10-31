import requests

class SendSMS:
    # BASE_URL = 'https://notify.eskiz.uz/api'
    def __init__(self, email: str, password: str) -> None:
        self.BASE_URL: str = 'https://notify.eskiz.uz/api'
        self.email: str = email
        self.password: str = password

    def get_token(self) -> str:
        endpoint: str = f"{self.BASE_URL}/auth/login"
        payload: dict = {
            'email': self.email,
            'password': self.password,
        }
        files: list = []
        headers: dict = {}
        req = requests.request("POST", endpoint, headers=headers, files=files, data=payload)
        token: str = req.json()['data']['token']
        return token


    def _call(self, method: str, endpoint: str, body: dict) -> None:
        token: str = self.get_token()
        headers: dict = {
            'Authorization': f"Bearer {token}"
        }
        req = requests.request(method, endpoint, headers=headers, data=body)
        return req 
    
    def refresh_token(self) -> None:
        endpoint: str = f"{self.BASE_URL}/auth/refresh"
        payload:dict = {
            'email': self.email,
            'password': self.password
        }
        req = self._call('PATCH', endpoint, payload)
        
    def delete_token(self) -> None:
        endpoint: str = f"{self.BASE_URL}/auth/invalidate"
        payload: dict = {
            'email': self.email,
            'password': self.password
        } 
        req = self._call('DELETE', endpoint, payload)

    
    def get_user_info(self):
        endpoint = f"{self.BASE_URL}/auth/user"
        payload = {}
        req = self._call('GET', endpoint, payload)
        print(req)


    def send_sms(self, message: str, phone: str) -> None:
        endpoint: str = f"{self.BASE_URL}/message/sms/send"
        payload: dict = {
            'mobile_phone': phone,
            'message': message,
            'from': '4546',
            'callback_url': 'http://0000.uz/test.php'
        }
        method: str = "POST"
        try:
            req = self._call(method, endpoint, payload)
            if req.status_code == 200:
                print("SMS sent successfully")
            else:
                print("Can not send sms ")
        except Exception as e:
            print("Error ", e)
            return f"Error: {e}"

    def send_global_sms(self, phone: str, message: str, country_code: str) -> None:
        endpoint: str = f"{self.BASE_URL}/message/sms/send-global"
        payload: dict = {
            'mobile_phone': phone, 
            'country_code': country_code,
            'message': message, 
            'callback_url': 'http://0000.uz/test-global.php',
            'unicode': '0'
        }
        method: str = "POST"
        try:
            req = self._call(method, endpoint, payload)
            if req.status_code == 200:
                print("SMS sent successfully")
            else:
                print("Can not send sms ")
        except Exception as e:
            print("Error ", e)
            return f"Error: {e}"
        