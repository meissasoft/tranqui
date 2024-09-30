from django.urls import path

from .views import UserListCreateView, UserRetrieveUpdateDeleteView

urlpatterns = [
    path('user/', UserListCreateView.as_view(), name='user-list-create'),
    path('user/<int:pk>/', UserRetrieveUpdateDeleteView.as_view(), name='user-detail'),
]
