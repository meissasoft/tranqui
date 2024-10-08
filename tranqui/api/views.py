from django.contrib.auth import authenticate
from rest_framework import generics, permissions
from rest_framework.permissions import AllowAny
from django.utils import timezone
from .utils import get_jwt_token, send_verification_email
from .serializers import *
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, OTP, Chat
import random


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        """
           Handles POST requests for user login.

           Args:
               request (Request): The request object containing the email and password.

           Returns:
               Response: A response object containing a success message if login
               is successful, or an error message if login fails.

           Raises:
               ValidationError: If the email or password is not provided.
           """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        if not email or not password:
            return Response({"message": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            user = authenticate(request, email=email, password=password)
            if user is not None:
                token = get_jwt_token(user)
                return Response({"message": "Login successful!", "token(access)": token.get('access')}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid password."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"message": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)


class ProfileUpdateView(generics.UpdateAPIView):
    serializer_class = ProfileUpdateSerializer
    http_method_names = ['put']

    def put(self, request, *args, **kwargs):
        """
           Handles PUT requests for updating user profiles.

           Args:
               request (Request): The request object containing the updated profile data.

           Returns:
               Response: A response object containing a success message if the
               profile is updated successfully.

           Raises:
               ValidationError: If the provided data is invalid.
           """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        user.username = serializer.validated_data.get('username', user.username)
        user.set_password(serializer.validated_data['password'])
        user.save()
        return Response({"message": "Profile updated successfully!"}, status=status.HTTP_200_OK)


class RegisterUserView(generics.CreateAPIView):
    # queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
           Handles POST requests for user registration.

           Args:
               request (Request): The request object containing the user registration data.

           Returns:
               Response: A response object containing a success message if the user
               is registered successfully and the OTP is sent, or an error message if
               the registration fails.

           Raises:
               ValidationError: If the provided data is invalid.
           """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp_code = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
            try:
                send_verification_email(user.email, otp_code)
                OTP.objects.create(email=user.email, otp=otp_code)
                return Response({"message": f"OTP sent to email {user.email}"}, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"Failed to send OTP": str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(generics.UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    http_method_names = ['patch']  # Allow only PATCH method

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
        new_password = serializer.validated_data['new_password']
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
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)


class VerifyOTPView(generics.CreateAPIView):
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
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()
        token = get_jwt_token(user)
        return Response({"msg": "OTP verified", "token(access)": token.get('access')}, status=status.HTTP_200_OK)


class ValidateResetCodeView(generics.GenericAPIView):
    serializer_class = ValidateResetCodeSerializer

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
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data['otp']
        password = serializer.validated_data['new_password']
        otp_record = OTP.objects.get(otp=otp)
        email = otp_record.email
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            return Response({"message": "Password has been updated successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


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
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.create_or_update_user()
        return Response({"message": "Login successful", "user_id": user.id}, status=status.HTTP_200_OK)


class WebSocketDocView(APIView):
    """
    WebSocket ChatBot API Documentation
    ---
    This endpoint allows the user to connect to the ChatBot WebSocket API.
    ## WebSocket Endpoint
    `ws://yourdomain.com/chatbot/`

    ### Sending a Message
    Send a JSON object with the prompt:
    ```json
    {
        "prompt": "Your question here"
    }
    ```

    ### Receiving a Response
    The server will respond with a JSON object:
    ```json
    {
        "response": "The answer to your question."
    }
    ```
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        return Response({"message": "WebSocket API documentation"})


class GetAllChatsView(generics.ListAPIView):
    """
    Retrieves all chats for the authenticated user.
    """
    serializer_class = ChatSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        chats = Chat.objects.filter(user=user)
        serializer = self.get_serializer(chats, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetChatsBySessionIDView(generics.ListAPIView):
    """
    Retrieves chats for a specific session ID.
    """
    serializer_class = ChatSerializer

    def get(self, request, session_id, *args, **kwargs):
        chats = Chat.objects.filter(session_id=session_id)
        serializer = self.get_serializer(chats, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
