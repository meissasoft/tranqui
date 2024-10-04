from django.contrib import admin
from .models import User, OTP, Chat


class ChatAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'prompt', 'response', 'session_id', 'created_at')


class OTPAdmin(admin.ModelAdmin):
    list_display = ('email', 'otp', 'id', 'created_at')


# Register your models here.
admin.site.register(User)
admin.site.register(Chat, ChatAdmin)
admin.site.register(OTP, OTPAdmin)
