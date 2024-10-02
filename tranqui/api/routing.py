
from django.urls import path
from .consumers import ChatbotConsumer  # Replace with your actual consumer

websocket_urlpatterns = [
    path('ws/chat/', ChatbotConsumer.as_asgi()),  # Ensure the correct path
]
