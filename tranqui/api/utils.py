import os
import smtplib
from email.mime.text import MIMEText
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from dotenv import load_dotenv

load_dotenv()

EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')


def get_jwt_token(user):
    """
    Generates JWT tokens for the given user.

    Args:
        user: The user instance for which the tokens are generated.

    Returns:
        dict: A dictionary containing 'refresh' and 'access' tokens.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def send_verification_email(email, otp_code):
    """
    Sends a verification email containing the OTP code to the specified email address.

    Args:
        email (str): The recipient's email address.
        otp_code (str): The OTP code to be sent in the email.

    Raises:
        SMTPAuthenticationError: If authentication fails during the email sending process.
    """
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp_code}."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = email

    try:
        print(EMAIL_SENDER, EMAIL_PASSWORD)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, "xtmr tqhv omjn epny")  # Use App Password
            server.sendmail(EMAIL_SENDER, email, msg.as_string())
        print("Email sent successfully!")
    except smtplib.SMTPAuthenticationError as e:
        print(f"Error: {e}")


def get_google_user_info(token: str):
    """
    Retrieves user information from Google using the provided OAuth token.

    Args:
        token (str): The OAuth token received from Google.

    Returns:
        dict: A dictionary containing user information retrieved from Google.

    Raises:
        HTTPError: If the request to the Google API fails.
    """
    userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
    response = requests.get(
        userinfo_endpoint, headers={"Authorization": f"Bearer {token}"}
    )
    response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)
    return response.json()
