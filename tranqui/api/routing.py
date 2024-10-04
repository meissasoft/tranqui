from django.urls import path
from .consumers import ChatbotConsumer

websocket_urlpatterns = [
    path('ws/chat/', ChatbotConsumer.as_asgi()),
]
