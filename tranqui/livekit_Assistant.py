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
            "You are a user friendly voice assistant created. Your interface with users will be voice. "
            "You should use short and concise responses, and avoiding usage of unpronouncable punctuation."
        ),
    )
    await ctx.connect(auto_subscribe=AutoSubscribe.AUDIO_ONLY)
    assistant = VoiceAssistant(
        vad=silero.VAD.load(),
        stt=deepgram.STT(model="nova-2-general", language="en-US"),
        llm=openai.LLM(model="gpt-3.5-turbo", temperature=0.5),
        tts=tts.StreamAdapter(tts=openai.TTS(voice="alloy"), sentence_tokenizer=tokenize.basic.SentenceTokenizer()),
        chat_ctx=initial_ctx,
    )
    assistant.start(ctx.room)

    await asyncio.sleep(1)
    await assistant.say("Hello, I am Tranqui AI assistant, how can I help you today!", allow_interruptions=True)
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
    def on_agent_speech_interrupted(msg: llm.ChatMessage):
        logger.info(msg="Agent interrupted")

if __name__ == "__main__":
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))
