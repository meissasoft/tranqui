import mimetypes
from datetime import datetime

import openai
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .serializers import ChatRequestSerializer
from django.utils import timezone
from django.conf import settings
from .models import User, Chat
from openai import OpenAI, OpenAIError
import json
import logging
import math
import string
import base64
import random
import asyncio
import os

logger = logging.getLogger(__name__)
client = OpenAI(api_key=settings.OPENAI_API_KEY)
OPENAI_TOKEN_LIMIT = settings.OPENAI_TOKEN_LIMIT
TOKEN_PER_WORD = settings.TOKEN_PER_WORD
SPEECH_FILE_PATH = "api/speech.mp3"
INPUT_FILE_PATH = "api/input.mp3"
BATCH_SIZE = 5


async def get_user(username):
    """Get a User instance by username asynchronously."""
    return await database_sync_to_async(User.objects.get)(username=username)


def generate_random_session_id(length=10):
    """Generate a random session ID of the specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class SpeechConsumer(AsyncWebsocketConsumer):
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
            greeting_message = self.get_greeting()
            await self.send(text_data=json.dumps({"message": greeting_message}))
        else:
            await self.close()

    def get_greeting(self):
        """Returns a short greeting based on the time of day and user's name."""
        current_hour = datetime.now().hour
        chatbot_name = settings.CHATBOT_NAME  # Fetch chatbot name from .env

        # Determine greeting based on the time of day
        if 5 <= current_hour < 12:
            time_greeting = "Good morning"
        elif 12 <= current_hour < 17:
            time_greeting = "Good afternoon"
        elif 17 <= current_hour < 20:
            time_greeting = "Good evening"
        else:
            time_greeting = "Good night"

        # Define 20 short, user-friendly greetings
        greetings = [
            f"{time_greeting}, {self.user.username}! I am {chatbot_name}. How’s your day going?",
            f"Hello, {self.user.username}! Its {chatbot_name}. What is on your mind today?",
            f"Hey {self.user.username}, {chatbot_name} here. How have you been?",
            f"Hi {self.user.username}, {chatbot_name} at your service! How can I assist?",
            f"{time_greeting}, {self.user.username}! Ready for a great conversation?",
            f"Hello {self.user.username}! {chatbot_name} here. Lets make today productive!",
            f"Hey {self.user.username}, hope you are doing well! {chatbot_name} here to help.",
            f"{time_greeting}, {self.user.username}! How is everything going on your end?",
            f"Hi {self.user.username}, {chatbot_name} here. How can I make your day easier?",
            f"Hey {self.user.username}! Let me know if you need help with anything.",
            f"Hi {self.user.username}, it is {chatbot_name}. How is your day been so far?",
            f"{time_greeting}, {self.user.username}. What can I do for you today?",
            f"Hello {self.user.username}! {chatbot_name} here. How is everything going?",
            f"Hey {self.user.username}, {chatbot_name} here. Ready to chat?",
            f"Hi {self.user.username}! How’s everything going today? {chatbot_name} is here to assist.",
            f"{time_greeting}, {self.user.username}! Hope you are doing great. What’s on your mind?",
            f"Hello {self.user.username}! Hows your day? {chatbot_name} is here for you.",
            f"Hey {self.user.username}, its {chatbot_name}! How can I assist today?",
            f"Hi {self.user.username}, hope you’re having a good one! Lets chat if you need anything.",
            f"{time_greeting}, {self.user.username}. How can I make your day better today?",
        ]

        # Randomly choose one greeting
        return random.choice(greetings)

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        logger.info(f"User {self.user.username} disconnected from WebSocket.")
            os.remove(SPEECH_FILE_PATH)
        await self.close()
        pass

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming WebSocket messages asynchronously."""
        try:
            audio = False
            if bytes_data is not None and text_data is None:
                logger.info("bytes data received")
                with open(INPUT_FILE_PATH, 'wb') as file:
                    file.write(bytes_data)
                transcribed_text = await self.transcribe_audio(INPUT_FILE_PATH)
                audio = True
                text_data_json = {
                    "prompt": transcribed_text
                }

            elif bytes_data is None and text_data is not None:
                logger.info("text data received")
                text_data_json = json.loads(text_data)
            serializer_data = {
                'session_id': self.session_id,
                'prompt': text_data_json.get('prompt'),
            }
            print("bytes_data", bytes_data)
            serializer = ChatRequestSerializer(data=serializer_data)
            serializer.is_valid(raise_exception=True)
            response_content = await self.process_prompt(serializer.validated_data, user=self.user, audio=audio)
            await self.send(text_data=json.dumps(response_content))

        except json.JSONDecodeError:
            logger.error("Invalid JSON received.")
            await self.send(text_data=json.dumps({'error': 'Invalid JSON format'}))
        except Exception as e:
            logger.exception("Error in WebSocket receive method.")
            await self.send(text_data=json.dumps({'error': 'An unexpected error occurred.'}))

    async def process_prompt(self, validated_data, user, audio):
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
                if audio:
                    if os.path.exists(SPEECH_FILE_PATH):
                    response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=messages,
                        stream=True
                    )
                    batch_count = 0
                    complete_response = ""
                    response_string = ""
                    for chunk in response:
                        if chunk.choices[0].delta.content is not None:
                            response_string = response_string + chunk.choices[0].delta.content
                            batch_count += 1
                            if batch_count >= BATCH_SIZE:
                                try:
                                    await self.text_to_speech(response_string)
                                except Exception as e:
                                    logger.error(f"Speech to text conversion error: {str(e)}")
                                    return "Sorry, there was error  in converting speech to text."
                                complete_response = complete_response + response_string
                                response_string = ""
                                batch_count = 0

                    if batch_count != 0:
                        await self.text_to_speech(response_string)
                    complete_response = complete_response + response_string
                    assistant_response = complete_response
                else:
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=messages
                    )
                    response_dict = object_to_dict(response)
                    assistant_response = response_dict['choices'][0]['message']['content']
                if not session_id:
                    session_id = generate_random_session_id()

            except OpenAIError as e:
                logger.error(f"OpenAI API error: {str(e)}")
                return "Sorry, there was an issue with the OpenAI API."
            except Exception as e:
                logger.error(f"Error in parsing chat completion response: {str(e)}")
                return "Sorry, there was an issue in handling response."

            total_tokens = calculate_token_count(assistant_response)
            await self.save_chat_response(user, prompt, assistant_response, session_id, total_tokens)
            return assistant_response
        except KeyError as e:
            logger.error(f"Key error in process_prompt: {str(e)}")
            return "Sorry, there was an issue processing your request."
        except Exception as e:
            logger.exception(f"Error in chat processing: {e}")
            return "Sorry, I couldn't process your request at the moment."

    async def transcribe_audio(self, file_path):
        """Transcribe incoming voice note"""
        audio_file = open(file_path, "rb")
        try:
            transcription = client.audio.transcriptions.create(
                model="whisper-1",
                file=audio_file
            )
            return transcription.text
        except (Exception, openai.BadRequestError) as e:
            raise e

    async def text_to_speech(self, text_chunk, model="tts-1", voice="alloy", buffer_size=1024):
        """Generate speech from text and send the audio data, also save it to a file."""
        try:
            with open(SPEECH_FILE_PATH, "ab") as audio_file:
                response = client.audio.speech.create(
                    model=model,
                    voice=voice,
                    input=text_chunk,
                )

                for data in response.iter_bytes(buffer_size):
                    await self.send(bytes_data=data)
                    audio_file.write(data)
                    await asyncio.sleep(0)

        except ConnectionError as ce:
            logging.error(f"Connection error occurred: {ce}")
        except ValueError as ve:
            logging.error(f"Value error: {ve}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

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
    return math.ceil(len(messages.split()) * float(TOKEN_PER_WORD))
