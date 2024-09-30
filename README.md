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
```
4. Make migrations and run the project
```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:9000
```

## API Documentation
- To access the Swagger UI, navigate to:


```dtd
http://127.0.0.1:9000/swagger/
```
- To access ReDoc, navigate to
```dtd
http://127.0.0.1:9000/redoc/
```


**Note:** Ensure your PostgreSQL server is running and accessible before starting the project.

