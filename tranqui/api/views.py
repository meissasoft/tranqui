import jwt
from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.shortcuts import get_object_or_404
from livekit import api
from jwt import ExpiredSignatureError, InvalidTokenError
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, viewsets
from rest_framework.exceptions import NotFound, ValidationError, AuthenticationFailed
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
    IsAuthenticatedOrReadOnly,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from .models import *
from .utils import *


class UserRegistrationView(generics.CreateAPIView):
    """
    Handles user registration via POST requests.
    """

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        user = User.objects.filter(email=email).first()
        if user:
            if not user.is_verified:
                try:
                    send_otp(email=email)
                    return Response(
                        {
                            "message": f"This email is already registered but never verified. New OTP sent to {email}."
                        },
                        status=status.HTTP_200_OK,
                    )
                except Exception as e:
                    logger.error(f"Error sending OTP to {email}: {str(e)}")
                    return Response(
                        {"error": "Failed to send OTP."},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
            else:
                return Response(
                    data={"message": "A user with this email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save(
                    username=serializer.validated_data["email"], is_verified=False
                )
                send_otp(email=email)
                return Response(
                    {"message": f"OTP sent to {email}"}, status=status.HTTP_201_CREATED
                )
            except Exception as e:
                logger.error(f"Error during registration: {str(e)}")
                return Response(
                    {
                        "error": f"An error occurred while registering. Please try again later: {e}"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(generics.GenericAPIView):
    """
    Handles user login.
    """

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                data={"error": "Invalid email or password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        try:
            user = User.objects.filter(email=email).first()
            if not check_password(password, user.password):
                return Response(
                    data={"message": "Invalid password."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not user.is_verified:
                return Response(
                    data={"message": "This account is unverified."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            token = get_jwt_token(user)
            logger.info(f"Login successful for user: {email}")
            return Response(
                data={"message": "Login successful!", "token": token.get("access")},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            logger.error(
                f"Login attempt failed. User with email: {email} does not exist."
            )
            return Response(
                data={"message": "User does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during login for {email}: {str(e)}"
            )
            return Response(
                data={"message": "An error occurred while trying to log in."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserProfileUpdateView(generics.UpdateAPIView):
    serializer_class = UserProfileSerializer
    http_method_names = ["put"]
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            with transaction.atomic():
                user = serializer.save()
                if "password" in serializer.validated_data:
                    user.set_password(serializer.validated_data["password"])
                    user.save()
            return Response(
                {"message": "Profile updated successfully!"}, status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(
                f"Unexpected error while updating profile for {request.user.email}: {str(e)}"
            )
            return Response(
                {
                    "error": "An unexpected error occurred while updating your profile. Please try again later."
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PasswordResetRequestView(generics.UpdateAPIView):
    serializer_class = PasswordResetSerializer
    http_method_names = ["patch"]
    permission_classes = [AllowAny]

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        if serializer.is_valid():
            send_otp(email=email)
            return Response(
                {"message": f"OTP sent to email {email}"},
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerificationView(generics.GenericAPIView):
    serializer_class = PasswordChangeConfirmationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            otp = serializer.validated_data["otp"]
            new_password = serializer.validated_data["new_password"]
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            otp_record = OTP.objects.get(otp=otp)
            if not otp_record.is_valid():
                logger.warning(f"OTP expired for email: {otp_record.email}")
                return Response(
                    {"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST
                )
            user = User.objects.filter(email=otp_record.email).first()
            user.set_password(new_password)
            user.save()
            otp_record.delete()
            logger.info(f"Password reset successfully for user: {otp_record.email}")
            return Response(
                {"message": "Password has been updated successfully."},
                status=status.HTTP_200_OK,
            )
        except OTP.DoesNotExist:
            logger.warning("Invalid OTP provided.")
            return Response(
                {"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )
        except User.DoesNotExist:
            logger.error(f"User not found for email: {otp_record.email}")
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"An error occurred while resetting the password: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class OTPVerificationView(generics.CreateAPIView):
    """
    Handles OTP verification for user accounts.
    """

    queryset = OTP.objects.all()
    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = serializer.validated_data["email"]
            otp_code = serializer.validated_data["otp"]
        try:
            otp_record = OTP.objects.get(email=email)
            if not otp_record:
                logger.warning(f"OTP not found in database against user: {email}")
                return Response(
                    data={"error": f"OTP not found in database against user: {email}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif otp_record.otp == otp_code:
                user = User.objects.filter(email=email).first()
                if user:
                    user.is_verified = True
                    user.save(update_fields=["is_verified"])
                    token = get_jwt_token(user)
                    if otp_record:
                        otp_record.delete()
                    logger.info(f"OTP verified successfully for user: {email}")
                    return Response(
                        data={
                            "message": "OTP verified successfully",
                            "token": token.get("access"),
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "user_id": user.id,
                        },
                        status=status.HTTP_200_OK,
                    )
            elif otp_record.otp != otp_code:
                logger.warning(f"Invalid OTP against user: {email}")
                return Response(
                    data={"error": f"Invalid OTP against user: {email}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except OTP.DoesNotExist:
            logger.error(f"No OTP found for the provided email: {email}")
            return Response(
                data={"error": f"No OTP found for the provided email: {email}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except User.DoesNotExist:
            logger.error(f"User with email `{email}` does not exists")
            raise NotFound(f"User with email `{email}` does not exists")


class OTPRetryView(generics.CreateAPIView):
    """
    Handles resending OTP to the user's email.
    """

    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = serializer.validated_data["email"]
            if not email:
                logger.error("Email is missing in the request.")
                return Response(
                    {"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
                )
            user = User.objects.get(email=email)
            if not user:
                logger.error(f"No user found with the email: {email}")
                return Response(
                    {"error": f"No user found with the email: {email}"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            send_otp(email=email)
            logger.info(f"New OTP resent successfully to email: {email}")
            return Response(
                {"message": "OTP resent successfully."}, status=status.HTTP_200_OK
            )


class GoogleAuthView(generics.GenericAPIView):
    serializer_class = GoogleSignInSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            token = request.data.get("token", None)
            if not token:
                return Response(
                    data={"error": "Token is missing."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            result = handle_google_auth(token)
            if result["error"]:
                return Response(
                    data={"error": result["message"]}, status=result["status"]
                )
            return Response(
                {
                    "message": result["message"],
                    "user_id": result.get("user_id"),
                    "token": result.get("token"),
                },
                status=result["status"],
            )
        except Exception as e:
            logger.error(f"Unexpected error during Google sign-in: {e}")
            return Response(
                data={"error": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ChatCreateView(generics.CreateAPIView):
    """
    Creates a new Chat instance for a given user.
    """

    serializer_class = ChatSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            prompt = request.data.get("prompt")
            response = request.data.get("response")
            conversation_id = request.data.get("conversation_id")
            try:
                data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                if data:
                    try:
                        user_id = data.get("user_id")
                        user = User.objects.get(id=user_id)
                        conversation = Conversation.objects.get(id=conversation_id)
                        chat = Chat(
                            user=user,
                            prompt=prompt,
                            response=response,
                            conversation=conversation,
                        )
                        chat.save()
                    except User.DoesNotExist:
                        return Response(
                            {"error": "User not found"},
                            status=status.HTTP_404_NOT_FOUND,
                        )
                    except InvalidTokenError:
                        return Response({"error": "Invalid token"}, status=401)
                    return Response(
                        {"message": "Chat created successfully"},
                        status=status.HTTP_201_CREATED,
                    )
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=401)
        else:
            return Response({"error": "Invalid token header"}, status=401)


class ChatListView(APIView):
    """
    Retrieves a list of Chat instances and their associated conversation details for a given conversation ID.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name="conversation_id",
                in_=openapi.IN_QUERY,
                description="ID of the conversation to filter chats",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ]
    )
    def get(self, request, *args, **kwargs):
        conversation_id = request.query_params.get("conversation_id")
        if not conversation_id:
            raise ValidationError(
                {"error": "conversation_id query parameter is required."}
            )
        conversation = get_object_or_404(Conversation, id=conversation_id)
        chats = Chat.objects.filter(conversation_id=conversation_id)
        conversation_data = ConversationSerializer(conversation).data
        chats_data = ChatSerializer(chats, many=True).data
        response_data = {"conversation": conversation_data, "chats": chats_data}
        return Response(response_data)


class GenerateLiveKitTokenView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name="room",
                in_=openapi.IN_QUERY,
                description="Room name",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                name="conversation_id",
                in_=openapi.IN_QUERY,
                description="Conversation id",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                name="identity",
                in_=openapi.IN_QUERY,
                description="User identity",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ]
    )
    def get(self, request, *args, **kwargs):
        try:
            api_key = settings.LIVEKIT_API_KEY
            api_secret = settings.LIVEKIT_API_SECRET
            room_name = request.query_params.get("room")
            conversation_id = request.query_params.get("conversation_id")
            identity = request.query_params.get("identity")
            if not all([room_name, conversation_id, identity]):
                return Response(
                    {
                        "error": "Parameters 'conversation_name', 'room', and 'identity' are required."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            current_user = User.objects.get(email=self.request.user)
            generated_room_name = (
                f"{room_name}-{generate_random_code()}-conversation_id{conversation_id}"
            )
            token = (
                api.AccessToken(api_key, api_secret)
                .with_identity(identity)
                .with_name("Tranqui AI Assistant")
                .with_grants(
                    api.VideoGrants(
                        room_join=True,
                        room=generated_room_name,
                    )
                )
            )
            return Response({"Livekit access token": token.to_jwt()})
        except Exception as e:
            return Response(data={"error": e}, status=status.HTTP_400_BAD_REQUEST)


class ConversationCreateView(APIView):
    """
    Create a new Conversation for the currently logged-in user.
    The 'name' field is passed as a query parameter.
    """

    permission_classes = [IsAuthenticatedOrReadOnly]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                "name",
                openapi.IN_QUERY,
                description="The name of the conversation.",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ]
    )
    def post(self, request, *args, **kwargs):
        # Ensure the user is authenticated
        if not request.user.is_authenticated:
            raise ValidationError("User is not authenticated.")

        # Fetch the 'name' from query params
        conversation_name = request.query_params.get("name")
        if not conversation_name:
            raise ValidationError("The 'name' parameter is required.")

        conversation_data = request.data
        conversation_data["name"] = conversation_name
        conversation_data["user"] = (
            request.user.id
        )  # Associate the conversation with the logged-in user

        serializer = ConversationSerializer(data=conversation_data)
        if serializer.is_valid():
            serializer.save(user=request.user)  # Ensure the user remains the same
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ConversationListView(APIView):
    """
    Fetch all conversations for the currently logged-in user.
    """

    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, *args, **kwargs):
        user = request.user
        conversations = Conversation.objects.filter(user=user)
        serializer = ConversationSerializer(conversations, many=True)
        return Response(serializer.data)


class ConversationDetailView(APIView):
    """
    Retrieve, update, or delete a conversation for the currently logged-in user.
    """

    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_object(self, conversation_id):
        return get_object_or_404(
            Conversation, id=conversation_id, user=self.request.user
        )

    def get(self, request, conversation_id, *args, **kwargs):
        conversation = self.get_object(conversation_id)
        serializer = ConversationSerializer(conversation)
        return Response(serializer.data)

    def put(self, request, conversation_id, *args, **kwargs):
        conversation = self.get_object(conversation_id)
        serializer = ConversationSerializer(
            conversation, data=request.data, partial=False
        )
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, conversation_id, *args, **kwargs):
        conversation = self.get_object(conversation_id)
        serializer = ConversationSerializer(
            conversation, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, conversation_id, *args, **kwargs):
        conversation = self.get_object(conversation_id)
        conversation.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ConversationHistoryView(generics.ListAPIView):
    """
    Fetch all chats for the currently logged-in user.
    """

    serializer_class = ConversationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Use the currently logged-in user
        user = self.request.user
        print("user", user)

        # Log the incoming request and token information
        auth_header = self.request.META.get("HTTP_AUTHORIZATION", None)
        print("self.request.META.", self.request.META)
        print("auth_header", auth_header)

        return Conversation.objects.filter(user=user)


class CurrentUserConversationHistoryView(generics.ListCreateAPIView):
    """
    Fetch all chats for the currently logged-in user.
    """

    serializer_class = ConversationSerializer
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Use the currently logged-in user
        user = self.request.user
        print("user", user)
        auth_header = self.request.META.get("HTTP_AUTHORIZATION", None)
        if not auth_header:
            auth_header = self.request.META.get("HTTP_X_AUTHORIZATION", None)
            if auth_header:
                try:
                    # Assuming the token is a JWT token
                    token = auth_header.split(" ")[1]
                    decoded_token = jwt.decode(
                        token, settings.SECRET_KEY, algorithms=["HS256"]
                    )
                    user_id = decoded_token.get("user_id")
                    return Conversation.objects.filter(user=user_id)
                except (
                    jwt.ExpiredSignatureError,
                    jwt.InvalidTokenError,
                    User.DoesNotExist,
                ):
                    raise AuthenticationFailed("Invalid token or user does not exist")
        print("self.request.META.", self.request.META)
        print("auth_header", auth_header)


class FacebookAuthView(generics.GenericAPIView):
    serializer_class = FacebookSignInSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            result = handle_facebook_auth(serializer.validated_data["token"])
            return Response(
                {
                    "message": result["message"],
                    "user_id": result.get("user_id"),
                    "token": result.get("token"),
                },
                status=result["status"],
            )
        except Exception as e:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
