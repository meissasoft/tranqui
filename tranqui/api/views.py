from django.contrib.auth.models import User
from rest_framework import generics

from .serializers import UserSerializer


# List all users and create new user
class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


# Retrieve, update, and delete a single user
class UserRetrieveUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
