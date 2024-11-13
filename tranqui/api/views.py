import logging
import string
from django.db import transaction, DatabaseError
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from jwt import ExpiredSignatureError, InvalidTokenError
from livekit import api
import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from requests import HTTPError
from rest_framework import generics
from rest_framework.exceptions import NotFound, NotAuthenticated
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils import timezone
from rest_framework.views import APIView
from .utils import get_jwt_token, send_verification_email
from .serializers import *
from rest_framework import status
from rest_framework.response import Response
from .models import User, OTP, Chat
import random

logger = logging.getLogger(__name__)


class LoginView(generics.GenericAPIView):
    """
    Handles user login.
    """
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for user login.

        Args:
            request (Request): The request object containing email and password.

        Returns:
            Response: A response object with a success message and JWT token if login
            is successful, or an error message if login fails.

        Raises:
            ValidationError: If email or password are invalid or authentication fails.
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
        try:
            user = authenticate(request, email=email, password=password)
            if user is not None:
                if not user.is_active:
                    logger.warning(f"Inactive account login attempt: {email}")
                    return Response(
                        data={
                            "message": "This account is inactive."
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
                token = get_jwt_token(user)
                logger.info(f"Login successful for user: {email}")
                return Response(
                    data={
                        "message": "Login successful!",
                        "Access Token": token.get('access')
                    },
                    status=status.HTTP_200_OK
                )
            else:
                logger.warning(f"Failed login attempt for email: {email} (Invalid credentials)")
                return Response(
                    data={
                        "message": "Invalid email or password."
                    },
                    status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            logger.error(f"Login attempt failed. User with email: {email} does not exist.")
            return Response(
                data={
                    "message": "User does not exist."
                },
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred during login for {email}: {str(e)}")
            return Response(
                data={
                    "message": "An error occurred while trying to log in."
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProfileUpdateView(generics.UpdateAPIView):
    """
    ProfileUpdateView allows authenticated users to update their profile details.
    It handles HTTP PUT requests and expects a valid profile update payload.
    """
    serializer_class = ProfileUpdateSerializer
    http_method_names = ['put']

    def put(self, request, *args, **kwargs):
        """
        Handles the profile update process.

        Raises:
            ValidationError: If the input data is invalid.
            NotAuthenticated: If the user is not authenticated.
            DatabaseError: If an error occurs while saving the data to the database.
        """
        # Ensure the request is made by an authenticated user
        if not request.user.is_authenticated:
            raise NotAuthenticated(detail="User must be authenticated to update the profile.")

        serializer = self.get_serializer(data=request.data)
        try:
            # Validate serializer data
            if not serializer.is_valid():
                return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user = serializer.validated_data
            if 'password' in serializer.validated_data:
                user.set_password(serializer.validated_data.get('password'))
                with transaction.atomic():
                    user.save()
                return Response(
                    data={"message": "Profile updated successfully!"},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    data={"error": f"Failed to update profile with email {user.email}."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except DatabaseError as e:
            logger.error(f"Database error during profile update: {e}")
            return Response(
                data={"error": "A database error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except AttributeError as e:
            logger.error(f"Attribute error during profile update: {e}")
            return Response(
                data={"error": f"Attribute error during profile update: {e}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(f"Unexpected error during profile update: {e}")
            return Response(
                data={"error": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RegisterUserView(generics.CreateAPIView):
    """
    Handles user registration via POST requests.

    Attributes:
        serializer_class (RegisterSerializer): Serializer for user registration.
        permission_classes (list): List of permissions for this view.
    """
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for user registration.

        Args:
            request (Request): The request object containing user registration data.

        Returns:
            Response: A response containing a success message if the user
            is registered successfully and the OTP is sent, or an error message
            if registration fails.

        Raises:
            ValidationError: If the provided data is invalid.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp_code = self.generate_otp()
            email = serializer.validated_data.get('email')
            try:
                self.send_otp_email(email, otp_code)
                OTP.objects.create(email=email, otp=otp_code)
                return Response({"message": f"OTP sent to {email}"}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error sending OTP to {email}: {str(e)}")
                return Response({"error": "Failed to send OTP."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def generate_otp():
        """Generates a 6-digit OTP."""
        return str(random.randint(100000, 999999))

    @staticmethod
    def send_otp_email(email, otp_code):
        """Sends the OTP to the user's email."""
        send_verification_email(email, otp_code)


class ResetPasswordView(generics.UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    http_method_names = ['patch']

    def patch(self, request, *args, **kwargs):
        """
            Handles PATCH requests for resetting user passwords.

            Args:
                request (Request): The request object containing the email and new password.

            Returns:
                Response: A response object containing a success message if the OTP
                is sent successfully, or an error message if the request fails.

            Raises:
                ValidationError: If the provided data is invalid.
            """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        if serializer.is_valid():
            otp_code = str(random.randint(100000, 999999))  # Generate a 6-digit OTP

            try:
                send_verification_email(email, otp_code)
                # OTP.objects.create(email=email, otp=otp_code)
                OTP.objects.update_or_create(
                    email=email,
                    defaults={
                        'otp': otp_code,
                        'created_at': timezone.now()
                    },
                )
                return Response({"message": f"OTP sent to email {email}"}, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({"message": "Verify the OTP to proceed further."}, status=status.HTTP_200_OK)


class VerifyOTPView(generics.CreateAPIView):
    """
    Handles OTP verification for user accounts.

    Attributes:
        queryset (QuerySet): The queryset for OTP objects.
        serializer_class (VerifyOTPSerializer): Serializer for verifying the OTP.
    """
    queryset = OTP.objects.all()
    serializer_class = VerifyOTPSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for verifying the OTP.

        Args:
            request (Request): The request object containing the email and OTP.

        Returns:
            Response: A response object containing a success message and JWT token
            if the OTP verification is successful, or an error message if the
            verification fails.

        Raises:
            ValidationError: If the provided OTP is invalid or expired.
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp']

        try:
            otp_record = OTP.objects.get(email=email, otp=otp_code)
            if not otp_record.is_valid():
                logger.warning(f"OTP expired for email: {email}")
                return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(email=email)
            user.is_verified = True
            user.save()
            token = get_jwt_token(user)
            otp_record.delete()
            logger.info(f"OTP verified successfully for user: {email}")
            return Response({"msg": "OTP verified successfully", "token": token.get('access')},
                            status=status.HTTP_200_OK)
        except OTP.DoesNotExist:
            logger.error(f"Invalid OTP attempt for email: {email}")
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            logger.error(f"User not found during OTP verification for email: {email}")
            raise NotFound("User not found.")


class VerifyResetCodeView(generics.GenericAPIView):
    serializer_class = VerifyResetCodeSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for validating the OTP and resetting the password.

        Args:
            request (Request): The request object containing the OTP and new password.

        Returns:
            Response: A response object containing a success message if the password
            reset is successful, or an error message if the user is not found or OTP
            validation fails.

        Raises:
            ValidationError: If the provided OTP is invalid or expired.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            otp_record = OTP.objects.get(otp=otp)
            if not otp_record.is_valid():
                logger.warning(f"OTP expired for email: {otp_record.email}")
                return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
            email = otp_record.email
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            otp_record.delete()
            logger.info(f"Password reset successfully for user: {email}")
            return Response({"message": "Password has been updated successfully."}, status=status.HTTP_200_OK)
        except OTP.DoesNotExist:
            logger.warning("Invalid OTP provided.")
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            logger.error(f"User not found for email: {email}")
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"An error occurred while resetting the password: {str(e)}")
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleSignInView(generics.GenericAPIView):
    serializer_class = GoogleSignInSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for Google sign-in.

        Args:
            request (Request): The request object containing the Google OAuth token.

        Returns:
            Response: A response object containing a success message and the user ID
            upon successful login, or an error message if validation fails.

        Raises:
            ValidationError: If the provided token is invalid or user information
            cannot be retrieved.
        """
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.create_or_update_user()
                return Response({"message": "Login successful", "user_id": user.id}, status=status.HTTP_200_OK)
            else:
                return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except HTTPError as e:
            # Log HTTPError and return a more informative response
            logger.error(f"HTTP error during Google sign-in: {e}")
            return Response(data={"error": f"HTTP error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            # Handle specific validation errors
            logger.error(f"Validation error: {e}")
            return Response(data={"error": "Invalid data received"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # General exception handling for any unexpected errors
            logger.error(f"Unexpected error during Google sign-in: {e}")
            return Response(data={"error": "An unexpected error occurred. Please try again later."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAllChatsView(generics.ListAPIView):
    """
    Retrieves all chats for the authenticated user.
    """
    serializer_class = ChatSerializer

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            if user.is_anonymous:
                return Response({"error": "Authentication credentials were not provided."},
                                status=status.HTTP_401_UNAUTHORIZED)
            chats = Chat.objects.filter(user=user)
            serializer = self.get_serializer(chats, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"error": e}, status=status.HTTP_400_BAD_REQUEST)


class CreateChatView(generics.CreateAPIView):
    """
    Creates a new Chat instance for a given user.
    """
    serializer_class = ChatSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            prompt = request.data.get('prompt')
            response = request.data.get('response')
            try:
                data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                if data:
                    try:
                        user_id = data.get("user_id")
                        user = User.objects.get(id=user_id)
                        chat = Chat(user=user, prompt=prompt, response=response)
                        chat.save()
                    except User.DoesNotExist:
                        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                    except InvalidTokenError:
                        return Response({"error": "Invalid token"}, status=401)
                    return Response({"message": "Chat created successfully"}, status=status.HTTP_201_CREATED)
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=401)
        else:
            return Response({"error": "Invalid token header"}, status=401)


class GetLiveKitToken(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='room', in_=openapi.IN_QUERY, description="Room name", type=openapi.TYPE_STRING, required=False
            ),
            openapi.Parameter(
                name='identity', in_=openapi.IN_QUERY, description="User identity", type=openapi.TYPE_STRING,
                required=False
            )
        ]
    )
    def get(self, request, *args, **kwargs):
        try:
            api_key = settings.LIVEKIT_API_KEY
            api_secret = settings.LIVEKIT_API_SECRET
            room_name = request.query_params.get('room')
            identity = request.query_params.get('identity')
            if not room_name or not identity:
                return Response(
                    {"error": "Both 'room' and 'identity' parameters are required."},
                    status=400
                )
            token = api.AccessToken(api_key, api_secret) \
                .with_identity(identity) \
                .with_name("Tranqui AI Assistant") \
                .with_grants(
                api.VideoGrants(
                    room_join=True,
                    room=room_name + generate_random_code(),
                )
            )
            return Response({"Livekit access token": token.to_jwt()})
        except Exception as e:
            return Response(data={"error": e}, status=status.HTTP_400_BAD_REQUEST)

def generate_random_code() -> str:
    random_code = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    return f"-{random_code}"
