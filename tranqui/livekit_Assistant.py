import asyncio

import requests
from django.conf import settings
from dotenv import load_dotenv
from livekit import rtc
from livekit.agents import AutoSubscribe, JobContext, WorkerOptions, cli, llm, tokenize
from livekit.agents import tts
from livekit.agents.voice_assistant import VoiceAssistant
from livekit.plugins import openai, silero, deepgram

load_dotenv()


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
            participant: rtc.RemoteParticipant,
    ):
        if track.kind == rtc.TrackKind.KIND_AUDIO:
            print("audio track: ", track)
            # asyncio.create_task(do_something(track))

        elif track.kind == rtc.TrackKind.KIND_VIDEO:
            print("video track: ", track)
            # asyncio.create_task(do_something(track))

    @assistant.on("user_speech_committed")
    def on_user_speech_committed(msg: llm.ChatMessage):
        nonlocal current_prompt
        # Store the user prompt
        current_prompt = msg.content
        print("user message:", current_prompt)

    @assistant.on("agent_speech_committed")
    def on_agent_speech_committed(msg: llm.ChatMessage):
        if current_prompt:
            token = participant.identity  # Assuming participant.identity holds the token
            room = ctx.room.name
            print("room in livekit:", room)
            print("identity in livekit:", token)
            identity_list = ctx.room.remote_participants.keys()
            user_identity = list(identity_list)[0]
            print("user:", user_identity)

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
                    print("Chat successfully saved to Django server.")
                else:
                    print("Failed to save chat:", response.json())
            except requests.exceptions.RequestException as e:
                print("Error connecting to Django server:", e)

            print("Conversation updated:", current_prompt, "->", msg.content)

if __name__ == "__main__":
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))
