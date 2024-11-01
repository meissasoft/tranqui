import base64
import uuid
from datetime import datetime
import aio_pika
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
import random
import asyncio
import os
import requests

logger = logging.getLogger(__name__)
client = OpenAI(api_key=settings.OPENAI_API_KEY)
OPENAI_TOKEN_LIMIT = settings.OPENAI_TOKEN_LIMIT
TOKEN_PER_WORD = settings.TOKEN_PER_WORD
SPEECH_FILE_PATH = settings.SPEECH_FILE_PATH
INPUT_FILE_PATH = settings.INPUT_FILE_PATH
BATCH_SIZE = int(settings.BATCH_SIZE)
BUFFER_SIZE = int(settings.BUFFER_SIZE)
DEEPGRAM_URL = settings.DEEPGRAM_URL
DEEPGRAM_API_KEY = settings.DEEPGRAM_API_KEY
RABBITMQ_URL = settings.RABBITMQ_URL


class SpeechConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exchange = None
        self.response_queue = None
        self.transcribed_text_queue = None
        self.audio_queue = None
        self.connection = None
        self.user = None
        self.session_id = None
        self.request_id = None
        self.active_tasks = {}

    async def connect(self):
        """Handle WebSocket connection."""
        self.session_id = self.scope['url_route']['kwargs'].get('session_id')
        self.user = self.scope.get('user')
        if self.user is not None and self.user.is_authenticated:
            await self.accept()
            await self.setup_rabbitmq_queues()
            asyncio.create_task(self.forward_messages_to_ws())
            # await self.publish_response_to_ws(message_text=(self.get_greeting()))
            await self.send(text_data=json.dumps({"message": self.get_greeting()}))
        else:
            await self.close()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        logger.info(f"User {self.user.username} disconnected from WebSocket.")
        if os.path.exists(SPEECH_FILE_PATH):
            os.remove(SPEECH_FILE_PATH)
        await self.close()

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming WebSocket messages asynchronously."""
        try:
            audio = False
            self.request_id = self.generate_request_id()
            if bytes_data is not None and text_data is None:
                audio = True
                if self.user in self.active_tasks:
                    task = self.active_tasks.pop(self.user)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        print(f"Task for user {self.user} was canceled.")
                    except Exception as e:
                        print(f"Error during task cancellation: {e}")
                # print("bytes data received", bytes_data, flush=True)
                encoded_data = base64.b64encode(bytes_data).decode('utf-8')

                message_body = self.create_message_body(data=encoded_data)
                await self.exchange.publish(
                    aio_pika.Message(body=json.dumps(message_body).encode('utf-8')),
                    routing_key='audio_queue_routing_key'  # Ensure this matches the queue binding
                )
                # transcribed_text = await self.transcribe_audio(INPUT_FILE_PATH)

                asyncio.create_task(self.deepgram_transcribe_audio(INPUT_FILE_PATH))
                # asyncio.create_task(self.consume_text_queue(audio=audio))

            elif bytes_data is None and text_data is not None:
                print("text data received", text_data, flush=True)
                serializer_data = {
                    'session_id': self.session_id,
                    'prompt': json.loads(text_data).get('prompt')
                }
                message_body = self.create_message_body(data=serializer_data)
                await self.exchange.publish(
                    aio_pika.Message(body=json.dumps(message_body).encode('utf-8')),
                    routing_key='text_queue_routing_key'
                )
            asyncio.create_task(self.consume_text_queue(audio=audio))
            await self.cleanup_tasks()

        except json.JSONDecodeError:
            logger.error("Invalid JSON received.")
            await self.send(text_data=json.dumps({'error': 'Invalid JSON format'}))
        except Exception as e:
            logger.exception("Error in WebSocket receive method.")
            await self.send(text_data=json.dumps({'error': f'An unexpected error occurred ({e})'}))

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
                        model="gpt-3.5-turbo",
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
            message_body = self.create_message_body(data=assistant_response)
            await self.exchange.publish(
                aio_pika.Message(body=json.dumps(message_body).encode('utf-8')),
                routing_key='response_queue_routing_key'
            )
            print("self.active_tasks", self.active_tasks)

        except KeyError as e:
            logger.error(f"Key error in process_prompt: {str(e)}")
            return "Sorry, there was an issue processing your request."
        except Exception as e:
            logger.exception(f"Error in chat processing: {e}")
            return "Sorry, I couldn't process your request at the moment."

    async def transcribe_audio(self, file_path):
        """Transcribe incoming voice note"""
        audio_file = open(file_path, "rb")
        print("audio_file: ", audio_file)
        data_content = audio_file.read()
        print("data_content: ", data_content)
        try:
            transcription = client.audio.transcriptions.create(
                model="whisper-1",
                file=audio_file
            )
            print('transcribed text from OPEN AI: ', transcription.text)
            return transcription.text
        except (Exception, openai.BadRequestError) as e:
            raise e

    async def text_to_speech(self, text_chunk, model="tts-1", voice="alloy", buffer_size=BUFFER_SIZE):
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

    async def deepgram_transcribe_audio(self, audio_file_path):
        async with self.audio_queue.iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process():
                    decoded_body = message.body.decode('utf-8')
                    message_data = json.loads(decoded_body)
                    data = message_data['data']
                    with open(INPUT_FILE_PATH, 'wb') as file:
                        file.write(base64.b64decode(data))
                    with open(audio_file_path, 'rb') as audio:
                        headers = {
                            'Authorization': f"Token {DEEPGRAM_API_KEY}",
                            'Content-Type': 'audio/wav',
                        }
                        response = requests.post(DEEPGRAM_URL, headers=headers, data=audio)
                        if response.status_code == 200:
                            transcribed_text = \
                                response.json().get('results', {}).get('channels', [])[0].get('alternatives', [])[
                                    0].get(
                                    'transcript', '')
                            print("transcribed text from DEEP GRAM: ", transcribed_text)
                            message_body = self.create_message_body(data=transcribed_text)
                            await self.exchange.publish(
                                aio_pika.Message(body=json.dumps(message_body).encode('utf-8')),
                                routing_key='text_queue_routing_key'
                            )
                        else:
                            raise Exception(f"Error in transcription from DEEP GRAM: {response.text}")
                # await message.ack()

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
            f"Hello, {self.user.username}! It's {chatbot_name}. What is on your mind today?",
            f"Hey {self.user.username}, {chatbot_name} here. How have you been?",
            f"Hi {self.user.username}, {chatbot_name} at your service! How can I assist?",
            f"{time_greeting}, {self.user.username}! Ready for a great conversation?",
            f"Hello {self.user.username}! {chatbot_name} here. Let's make today productive!",
            f"Hey {self.user.username}, hope you are doing well! {chatbot_name} here to help.",
            f"{time_greeting}, {self.user.username}! How is everything going on your end?",
            f"Hi {self.user.username}, {chatbot_name} here. How can I make your day easier?",
            f"Hey {self.user.username}! Let me know if you need help with anything.",
            f"Hi {self.user.username}, it is {chatbot_name}. How has your day been so far?",
            f"{time_greeting}, {self.user.username}. What can I do for you today?",
            f"Hello {self.user.username}! {chatbot_name} here. How is everything going?",
            f"Hey {self.user.username}, {chatbot_name} here. Ready to chat?",
            f"Hi {self.user.username}! How is everything going today? {chatbot_name} is here to assist.",
            f"{time_greeting}, {self.user.username}! Hope you are doing great. What is on your mind?",
            f"Hello {self.user.username}! How is your day? {chatbot_name} is here for you.",
            f"Hey {self.user.username}, it's {chatbot_name}! How can I assist today?",
            f"Hi {self.user.username}, hope you are having a good one. Let's chat if you need anything.",
            f"{time_greeting}, {self.user.username}. How can I make your day better today?",
        ]

        # Randomly choose one greeting
        return random.choice(greetings)

    async def publish_response_to_ws(self, message_text):
        message_body = self.create_message_body(data=message_text)
        await self.exchange.publish(
            aio_pika.Message(body=json.dumps(message_body).encode('utf-8')),
            routing_key='response_queue_routing_key'
        )

    async def consume_text_queue(self, audio: bool):
        while True:
            try:
                async with self.transcribed_text_queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            decoded_body = message.body.decode('utf-8')
                            message_data = json.loads(decoded_body)
                            transcribed_text = message_data['data']
                            print("transcribed text:   ", transcribed_text)
                            json_data = {
                                "prompt": transcribed_text
                            }
                            serializer_data = {
                                'session_id': self.session_id,
                                'prompt': json_data.get('prompt'),
                            }
                            serializer = ChatRequestSerializer(data=serializer_data)
                            serializer.is_valid(raise_exception=True)
                            self.active_tasks[self.user] = asyncio.create_task(self.process_prompt(serializer.validated_data, user=self.user,audio=audio))

            except aio_pika.exceptions.ChannelClosed as e:
                logger.error("Channel closed: %s", e)
                break  # Exit the loop if the channel is closed
            except json.JSONDecodeError as e:
                logger.error("Failed to decode JSON: %s", e)
                await message.reject(requeue=False)  # Reject the message without requeuing
            except Exception as e:
                logger.error("Error processing message: %s", e)
                await message.reject(requeue=True)  # Reject and requeue on error

    async def forward_messages_to_ws(self):
        async with self.response_queue.iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process():
                    decoded_body = message.body.decode('utf-8')
                    message_data = json.loads(decoded_body)
                    data = message_data['data']
                    print("data:", data)
                    await self.send(data)
                # await message.ack()

    async def setup_rabbitmq_queues(self):
        self.connection = await aio_pika.connect_robust(RABBITMQ_URL)
        channel = await self.connection.channel()
        self.exchange = await channel.declare_exchange('tranqui_exchange', aio_pika.ExchangeType.DIRECT)
        self.audio_queue = await channel.declare_queue('audio_queue')
        self.transcribed_text_queue = await channel.declare_queue('text_queue')
        self.response_queue = await channel.declare_queue('response_queue')
        await self.audio_queue.bind(self.exchange, routing_key='audio_queue_routing_key')
        await self.transcribed_text_queue.bind(self.exchange, routing_key='text_queue_routing_key')
        await self.response_queue.bind(self.exchange, routing_key='response_queue_routing_key')

    def create_message_body(self, data):
        return {
            'session_id': self.session_id,
            'request_id': self.request_id,
            'timestamp': datetime.now().isoformat(),  # Current timestamp in seconds
            'data': data
        }

    def generate_request_id(self):
        """Generate a unique request ID using UUID."""
        return str(uuid.uuid4())

    async def cleanup_tasks(self):
        """Remove completed tasks from active tasks."""
        for request_id, task in list(self.active_tasks.items()):
            if task.done():
                # Optionally, you can handle exceptions here
                self.active_tasks.pop(request_id)


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


async def get_user(username):
    """Get a User instance by username asynchronously."""
    return await database_sync_to_async(User.objects.get)(username=username)


def generate_random_session_id(length=10):
    """Generate a random session ID of the specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
