# Tranqui Project

This project uses PostgreSQL for the database. Please create a `.env` file in the root directory with the following structure:
Here is how to setup this project
1. Create a virtual environment
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```
2. Install the required packages
```bash
pip install -r requirements.txt
```
3. Set the database credentials in the `.env` file
```text
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_password
DB_HOST=your_server
DB_PORT=5432
EMAIL_SENDER=
EMAIL_PASSWORD=
DJANGO_SETTINGS_MODULE=
OPENAI_API_KEY=
OPENAI_TOKEN_LIMIT=
TOKEN_PER_WORD=
CHATBOT_NAME=
```
4. Make migrations and run the project
```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## API Documentation
- To access the Swagger UI, navigate to:


```dtd
http://127.0.0.1:8000/swagger/
```
- To access ReDoc, navigate to
```dtd
http://127.0.0.1:8000/redoc/
```
## Chatbot API Access

**WebSocket ChatBot API**

To access the WebSocket ChatBot API, connect to the following WebSocket endpoint:
```bash
ws://127.0.0.1:8000/ws/chat/
```
Send a JSON object with a message prompt
```json
{
   "prompt": "Your question here"
}
```
### Note for developers:
When testing the API, ensure that an authentication token is included in the request headers.
```
Authorization: <your_auth_token>
```e
Token can be obtained after every successfull login and register

**Note:** Ensure your PostgreSQL server is running and accessible before starting the project.

