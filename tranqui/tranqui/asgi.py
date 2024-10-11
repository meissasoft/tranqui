import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
# from api.consumers import ChatbotConsumer
from api.speech_to_speech_consumer import SpeechConsumer

from django.urls import re_path
from api.jwt_middleware import JWTAuthenticationMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tranqui.settings')
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JWTAuthenticationMiddleware(
        URLRouter(
            [
                re_path(r'ws/chat/(?P<session_id>\w+)?$', SpeechConsumer.as_asgi()),  # session_id is optional
            ]
        )
    ),
})
