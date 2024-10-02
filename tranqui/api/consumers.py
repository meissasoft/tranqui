import json
import openai
from channels.generic.websocket import AsyncWebsocketConsumer
from .serializers import *
from django.conf import settings


class ChatbotConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()  # Accept the WebSocket connection
        await self.send(text_data=json.dumps({"message": "WebSocket connection established"}))

    async def disconnect(self, close_code):
        pass  # Handle disconnection

    async def receive(self, text_data):
        """Handle incoming WebSocket messages asynchronously."""
        try:
            # Parse the incoming message using the serializer
            text_data_json = json.loads(text_data)
            serializer = ChatRequestSerializer(data=text_data_json)
            serializer.is_valid(raise_exception=True)  # Validate incoming data

            user_message = serializer.validated_data['prompt']

            # OpenAI API call (updated for OpenAI v1.0.0+)
            response = openai.completions.create(
                model="gpt-3.5-turbo-instruct",
                prompt=user_message
            )

            # Get the response content from OpenAI and strip leading/trailing whitespace
            assistant_reply = response.choices[0].text.strip()

            # Prepare the response data using the response serializer
            response_serializer = ChatResponseSerializer(data={'message': assistant_reply})
            response_serializer.is_valid(raise_exception=True)  # Validate response data

            # Send the response back to the WebSocket client in proper JSON format
            await self.send(text_data=json.dumps(response_serializer.data))

        except Exception as e:
            # Handle unexpected errors and send error response
            error_response = {'error': str(e)}
            await self.send(text_data=json.dumps(error_response))

    async def process_prompt(self, prompt):
        """Call to OpenAI API to get a response based on the prompt."""
        try:
            openai.api_key = settings.OPENAI_API_KEY  # Set your OpenAI API key

            # Call the OpenAI API asynchronously
            response = await openai.completions.create(
                model="gpt-3.5-turbo-instruct",  # You can use any model available to you
                prompt=prompt
            )

            # Extract the response text
            return response.choices[0].text.strip()

        except Exception as e:
            print(f"Error in OpenAI API call: {str(e)}")
            return "Sorry, I couldn't process your request at the moment."  # Fallback response

    def get_current_time(self):
        from django.utils import timezone
        return timezone.now()  # Get the current timestamp
