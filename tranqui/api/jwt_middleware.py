import logging

import jwt
from django.conf import settings
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from api.models import User

logger = logging.getLogger(__name__)


@database_sync_to_async
def get_user(user_id):
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


class JWTAuthenticationMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if path.startswith('/ws/'):
            headers = dict(scope['headers'])
            token = headers.get(b'authorization')
            if token:
                try:
                    token = token.decode()
                    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    scope['user'] = await get_user(payload['user_id'])
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError) as e:
                    logger.error("Error in JWT authentication: ", e)
                    scope['user'] = None
        else:
            scope['user'] = None
        return await super().__call__(scope, receive, send)
