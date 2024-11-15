import asyncio
import logging

import requests
from django.conf import settings
from dotenv import load_dotenv
from livekit import rtc
from livekit.agents import AutoSubscribe, JobContext, WorkerOptions, cli, llm, tokenize
from livekit.agents import tts
from livekit.agents.voice_assistant import VoiceAssistant
from livekit.plugins import openai, silero, deepgram

load_dotenv()

logger = logging.getLogger(__name__)

CHAT_API_URL = settings.CHAT_API_URL
conversation_history = {}


async def entrypoint(ctx: JobContext):
    initial_ctx = llm.ChatContext().append(
        role="system",
        text=(
            "You are a user-friendly voice assistant. Your interface with users will be voice. "
            "You should use short and concise responses, avoiding usage of unpronounceable punctuation."
        ),
    )
    await ctx.connect(auto_subscribe=AutoSubscribe.AUDIO_ONLY)

    # List of unique greeting messages
    greetings = [
        "Hi there! I'd love to get to know you better. What's your name?",
        "Hello! I'm here to help. Could you tell me your name to get started?",
        "Hey! Thanks for joining me. May I know your name?",
        "Hi! I'm excited to chat with you. What's your name?",
        "Greetings! To make this personal, could you share your name with me?",
        "Hello! Let's make this a bit more friendly. May I know your name?",
        "Hey there! I'd like to call you by name. What's your name?",
        "Hi! It's great to meet you. May I know what I should call you?",
        "Hello! Before we dive in, could you let me know your name?",
        "Hey! I'm here and ready to assist. Can you tell me your name first?",
    ]

    # Choose a random greeting message
    chosen_greeting = random.choice(greetings)

    assistant = VoiceAssistant(
        vad=silero.VAD.load(),
        stt=deepgram.STT(model="nova-2-general", language="en-US"),
        llm=openai.LLM(model="gpt-3.5-turbo", temperature=0.5),
        tts=tts.StreamAdapter(tts=openai.TTS(voice="alloy"), sentence_tokenizer=tokenize.basic.SentenceTokenizer()),
        chat_ctx=initial_ctx,
    )
    assistant.start(ctx.room)

    await asyncio.sleep(1)
    await assistant.say(source=chosen_greeting, allow_interruptions=True)
    current_prompt = None

    participant = await ctx.wait_for_participant()

    @ctx.room.on("track_subscribed")
    def on_track_subscribed(
            track: rtc.Track,
            publication: rtc.TrackPublication,
            remote_participant: rtc.RemoteParticipant,
    ):
        if track.kind == rtc.TrackKind.KIND_AUDIO:
            logger.info(msg=f"audio track: {track}")

        elif track.kind == rtc.TrackKind.KIND_VIDEO:
            logger.info(msg=f"video track: {track}")

    @assistant.on("user_speech_committed")
    def on_user_speech_committed(msg: llm.ChatMessage):
        nonlocal current_prompt
        current_prompt = msg.content
        logger.info(msg=f"user message: {current_prompt}")

    @assistant.on("agent_speech_committed")
    def on_agent_speech_committed(msg: llm.ChatMessage):
        if current_prompt:
            token = participant.identity
            room = ctx.room.name
            identity_list = ctx.room.remote_participants.keys()
            user_identity = list(identity_list)[0]
            data = {
                "user_key": user_identity,
                "prompt": current_prompt,
                "response": msg.content,
            }

            headers = {
                "Authorization": f"Bearer {token}"
            }

            try:
                response = requests.post(CHAT_API_URL, json=data, headers=headers)
                if response.status_code == 201:
                    logger.info(msg="Chat successfully saved to Django server.")
                else:
                    logger.info(msg=f"Failed to save chat:{response.json()}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error connecting to Django server:{e}")

            logger.info(msg=f"Conversation updated: {current_prompt}, -> {msg.content}")

    @assistant.on("agent_started_speaking")
    def on_agent_speech_started():
        logger.info(msg="Agent is speaking")

    @assistant.on("agent_speech_interrupted")
    def on_agent_speech_interrupted():
        logger.info(msg="Agent interrupted")

if __name__ == "__main__":
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))
