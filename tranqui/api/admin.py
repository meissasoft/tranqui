from django.contrib import admin
from .models import User, OTP, Chat, Conversation


class ChatAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'prompt', 'response', 'created_at', "conversation")


class OTPAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'otp', 'id', 'created_at')


class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'updated_at', 'created_at')


# Register your models here.
admin.site.register(User)
admin.site.register(Chat, ChatAdmin)
admin.site.register(Conversation, ConversationAdmin)
admin.site.register(OTP, OTPAdmin)
