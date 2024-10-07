import json
import logging
import math
import string
import random
from django.utils import timezone
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .serializers import ChatRequestSerializer
from django.conf import settings
from .models import User, Chat
from openai import OpenAI, OpenAIError

logger = logging.getLogger(__name__)
client = OpenAI(api_key=settings.OPENAI_API_KEY)
OPENAI_TOKEN_LIMIT = int(getattr(settings, "OPENAI_TOKEN_LIMIT", 5000))
TOKEN_PER_WORD = int(getattr(settings.TOKEN_PER_WORD, "0.57"))


async def get_user(username):
    """Get a User instance by username asynchronously."""
    return await database_sync_to_async(User.objects.get)(username=username)


def generate_random_session_id(length=10):
    """Generate a random session ID of the specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class ChatbotConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.session_id = None

    async def connect(self):
        """Handle WebSocket connection."""
        self.session_id = self.scope['url_route']['kwargs'].get('session_id')
        self.user = self.scope.get('user')
        if self.user is not None and self.user.is_authenticated:
            await self.accept()
            logger.info(f"User {self.user.username} connected via WebSocket.")
            await self.send(text_data=json.dumps({"message": "WebSocket connection established"}))
        else:
            await self.close()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        logger.info(f"User {self.user.username} disconnected from WebSocket.")
        pass

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming WebSocket messages asynchronously."""
        try:
            text_data_json = json.loads(text_data)
            serializer_data = {
                'session_id': self.session_id,
                'prompt': text_data_json.get('prompt'),
            }
            serializer = ChatRequestSerializer(data=serializer_data)
            serializer.is_valid(raise_exception=True)
            response_content = await self.process_prompt(serializer.validated_data, user=self.user)
            await self.send(text_data=json.dumps(response_content))

        except json.JSONDecodeError:
            logger.error("Invalid JSON received.")
            await self.send(text_data=json.dumps({'error': 'Invalid JSON format'}))
        except Exception as e:
            logger.exception("Error in WebSocket receive method.")
            await self.send(text_data=json.dumps({'error': 'An unexpected error occurred.'}))

    async def process_prompt(self, validated_data, user):
        """Process the user prompt and send it to OpenAI API."""
        try:
            prompt = validated_data['prompt']
            session_id = self.session_id
            if session_id:
                chats = await self.get_chats_by_session_id(user, session_id)
                reference_chunk = await self.get_token_limited_chats(chats)
                messages = reference_chunk
            else:
                messages = []
            messages.append({"role": "user", "content": prompt})
            try:
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=messages
                )
            except OpenAIError as e:
                logger.error(f"OpenAI API error: {str(e)}")
                return "Sorry, there was an issue with the OpenAI API."
            response_dict = object_to_dict(response)
            if session_id:
                assistant_response = response_dict['choices'][0]['message']['content']
            else:
                assistant_response = response_dict['choices'][0]['message']['content']
                session_id = generate_random_session_id()
            total_tokens = calculate_token_count(assistant_response)
            await self.save_chat_response(user, prompt, assistant_response, session_id, total_tokens)
            return assistant_response
        except KeyError as e:
            logger.error(f"Key error in process_prompt: {str(e)}")
            return "Sorry, there was an issue processing your request."
        except Exception as e:
            logger.exception(f"Error in chat processing: {e}")
            return "Sorry, I couldn't process your request at the moment."

    @database_sync_to_async
    def get_chats_by_session_id(self, user, session_id):
        """Fetch all chats for a given user and session ID."""
        return list(Chat.objects.filter(user=user, session_id=session_id))

    @database_sync_to_async
    def get_token_limited_chats(self, chats):
        """Limit chats based on token size."""
        messages = []
        total_tokens = 0
        token_limit = int(OPENAI_TOKEN_LIMIT)
        for chat in chats:
            if total_tokens >= token_limit:
                messages.pop(1)
                break
            chat_tokens = chat.total_tokens
            if total_tokens + chat_tokens <= token_limit:
                messages.append({"role": "user", "content": chat.prompt})
                messages.append({"role": "assistant", "content": chat.response})
                total_tokens += chat_tokens
        return messages

    @database_sync_to_async
    def save_chat_response(self, user, prompt, response, session_id, total_tokens):
        """Save the chat response to the database."""
        chat = Chat(
            user=user,
            prompt=prompt,
            response=response,
            session_id=session_id,
            created_at=timezone.now(),
            total_tokens=total_tokens
        )
        chat.save()


def object_to_dict(obj):
    """
    Convert an object to a dictionary, handling nested objects and lists.
    """
    if isinstance(obj, list):
        return [object_to_dict(item) for item in obj]
    elif hasattr(obj, "__dict__"):
        return {key: object_to_dict(value) for key, value in obj.__dict__.items()}
    else:
        return obj


def calculate_token_count(messages: str) -> int:
    # 750 tokens per 1000 words which equals to 0.75 token per word
    return math.ceil(len(messages.split()) * int(TOKEN_PER_WORD))
