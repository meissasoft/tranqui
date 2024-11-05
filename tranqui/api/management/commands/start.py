from django.core.management.base import BaseCommand
from livekit.agents import cli, WorkerOptions, Plugin
from livekit.agents.voice_assistant import VoiceAssistant
from livekit.plugins import openai, silero
from livekit.agents import llm, AutoSubscribe, JobContext
import asyncio


class Command(BaseCommand):
    help = 'Starts the LiveKit voice assistant agent'

    def __init__(self, stdout=None, stderr=None, no_color=False, force_color=False):
        super().__init__(stdout, stderr, no_color, force_color)
        self.assistant = None

    def handle(self, *args, **kwargs):
        """Handle the command to start the LiveKit voice assistant."""
        Plugin.register_plugin(openai.OpenAIPlugin())
        Plugin.register_plugin(silero.SileroPlugin())
        cli.run_app(WorkerOptions(entrypoint_fnc=self.run_livekit_voice_assistant))

    async def run_livekit_voice_assistant(self, context: JobContext):
        """Initialize and start the LiveKit voice assistant."""
        initial_context = llm.ChatContext().append(
            role="system",
            text=(
                "You are a user-friendly AI voice assistant and you should talk to the user like an actual human. Your "
                "interface with users will be voice. You should use short and concise responses, and avoid "
                "usage of unpronounceable punctuation."
            ),
        )
        await context.connect(auto_subscribe=AutoSubscribe.AUDIO_ONLY)

        self.assistant = VoiceAssistant(
            vad=silero.VAD.load(),
            stt=openai.STT(),
            llm=openai.LLM(),
            tts=openai.TTS(),
            chat_ctx=initial_context,
        )
        self.assistant.start(context.room)
        await asyncio.sleep(1)
        await self.assistant.say("Hey,I am Tranqui AI assistant. How can I help you today!", allow_interruptions=True)
