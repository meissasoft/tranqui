# Generated by Django 5.1.1 on 2024-11-21 10:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_conversation_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chat',
            name='tokens',
        ),
    ]
