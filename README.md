# Telefon orqali ro'yxatdan o'tish. Django rest framework, simple jwt va ESKIZ API ishlatilingan.
[![My Skills](https://skillicons.dev/icons?i=django&theme=dark)](https://skillicons.dev)

# Kerakli paketlar va kutubxonalar
```python 3.10.2 ```

Kerakli kutubxonalarni `pip install -r requirements.txt` orqali o'rnatish kerak.

# Ishga tushirish
```python manage.py migrate ```

```python manage.py runserver ```

Superuser yaratish uchun:
```python manage.py createsuperuser ``` va kerakli ma'lumotlarni kiriting.

Sayt ishga tushgandan so'ng `http://127.0.0.1:8000/admin/` orqali admin paneliga kirishingiz mumkin.

API endpointlari `http://127.0.0.1:8000/api/` orqali ko'rish mumkin.

API documentation `http://127.0.0.1:8000/swagger/` yoki `http://127.0.0.1:8000/redoc/` orqali ko'rish mumkin.


# Foydalanish
1. Superuser yaratish
2. Postman yoki boshqa API testlash uchun dastur yoki sayt orqali API endpointlari bilan ishlash
3. User yaratish
4. User login qilish
5. User tokeni orqali API endpointlari bilan ishlash

# API endpointlari

## Simple_jwt endpointlari:
1. `http://127.0.0.1:8000/api/token/` - User login(token hosil) qilish
2. `http://127.0.0.1:8000/api/token/refresh/` - User tokeni yangilash

## API doc endpointlari:
1. `http://127.0.0.1:8000/swagger/` - Swagger UI API doc
2. `http://127.0.0.1:8000/redoc/` - Redoc API doc

## User endpointlari:
1. `http://127.0.0.1:8000/api/users/` - Userlar ro'yxati
2. `http://127.0.0.1:8000/api/users/register/` - User yaratish
3. `http://127.0.0.1:8000/api/send-otp/` - Telefon raqamiga kod yuborish
4. `http://127.0.0.1:8000/api/validate-otp/` - Kodni tekshirish
5. `http://127.0.0.1:8000/api/users/login` - Tizimga kirish
6. `http://127.0.0.1:8000/api/logout/` - Tizimdan chiqish

### User yaratish
Telefon raqamiga `http://127.0.0.1:8000/api/send-otp/` orqali sms yuboriladi va o'sha smsni `http://127.0.0.1:8000/api/validate-otp/` orqali tekshiriladi. Agar tekshirish muvaffaqiyatli bo'lsa user yaratishga ruxsat beriladi. User yaratish uchun `http://127.0.0.1:8000/api/users/register/` endpointiga POST request yuboriladi. POST request body'si quyidagicha bo'lishi kerak:

```json
{
    "phone": "998901234567",
    "password": "1234",
}
```

### User login
User login qilish uchun `http://127.0.0.1:8000/api/users/login/` endpointiga POST request yuboriladi. POST request body'si quyidagicha bo'lishi kerak:

```json
{
    "phone": "998901234567",
    "password": "1234",
}
```

Response esa quiyidagicha qaytadi: 
```json 
{
    "token": {
        "access" : "<ACCESS_TOKEN>",
        "refresh": "<REFRESH_TOKEN>",
    },
    "user": "<USER_DATA>"
}
```



# Social links of author
Telegram: @komronbek_dev
