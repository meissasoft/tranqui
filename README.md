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
TOKEN_PER_WORD=
SPEECH_FILE_PATH=
INPUT_FILE_PATH=
BATCH_SIZE=
BUFFER_SIZE=
DEEPGRAM_URL=
DEEPGRAM_API_KEY=
RABBITMQ_URL=
LIVEKIT_API_KEY=
LIVEKIT_API_SECRET=
LIVEKIT_URL=
CHAT_API_URL=
CHAT_HISTORY_API_URL=
MAX_TOKENS=
TOKENS_PER_WORD=
INITIAL_SYSTEM_PROMPT=
STT_MODEL=
STT_LANGUAGE=
LLM_MODEL=
LLM_TEMPERATURE=
TTS_VOICE=
```
4. Make migrations and run the project
```bash
cd tranqui
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```
5. Start the livekit server on a seperate terminal window
```
python livekit_Assistant.py start
```

## API Documentation
- To access the Swagger UI, navigate to:


```dtd
http://127.0.0.1:8000/swagger/
```


### Note for developers:
When testing the API, ensure that an authentication token is included in the request headers.
```
Authorization: <your_auth_token>
```e
Token can be obtained after every successfull login and register

**Note:** Ensure your PostgreSQL server is running and accessible before starting the project.

