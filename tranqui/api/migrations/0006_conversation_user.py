# Generated by Django 5.1.1 on 2024-11-19 13:33

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_conversation_chat_tokens_chat_conversation'),
    ]

    operations = [
        migrations.AddField(
            model_name='conversation',
            name='user',
            field=models.ForeignKey(default=39, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]
