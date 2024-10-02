import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from api.consumers import ChatbotConsumer  # Adjust the import based on your project structure
from django.urls import path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'yourproject.settings')  # Change 'yourproject' to your actual project name

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            [
                path('ws/chat/', ChatbotConsumer.as_asgi()),  # Ensure this matches your WebSocket URL
            ]
        )
    ),
})
