import logging
import random
from typing import List, Dict
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
CHAT_HISTORY_API_URL = settings.CHAT_HISTORY_API_URL
MAX_TOKENS = settings.MAX_TOKENS
TOKENS_PER_WORD = settings.TOKENS_PER_WORD


async def fetch_chat_history(conversation_id: int) -> Dict:
    """Fetch previous chat responses for the given conversation ID."""
    try:
        response = requests.get(f"{CHAT_HISTORY_API_URL}?conversation_id={conversation_id}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch chat history for conversation ID {conversation_id}: {e}")
        return {}


def calculate_valid_responses(chats: List[Dict]) -> List[Dict[str, str]]:
    """
    Calculate total tokens and filter out prompt-response pairs exceeding the token limit.
    Returns a list of valid prompt-response dictionaries.
    """
    total_tokens = 0
    valid_responses = []

    for chat in chats:
        prompt = chat.get('prompt', '')
        response = chat.get('response', '')
        word_count = len(response.split())
        tokens = word_count * TOKENS_PER_WORD

        if total_tokens + tokens <= MAX_TOKENS:
            total_tokens += tokens
            valid_responses.append({prompt: response})
        else:
            break

    logger.debug(f"Total tokens used: {total_tokens}")
    return valid_responses


async def entrypoint(ctx: JobContext):
    initial_ctx = llm.ChatContext().append(
        role="system",
        text=random.choice(settings.INITIAL_SYSTEM_PROMPT),
    )
    initial_ctx.append(
        role="system",
        text="You are a therapist AI. Your role is to listen empathetically, understand human emotions, "
             "and respond with psychological insight.Approach conversations with care, sensitivity, "
             "and compassion. Recognize the emotions behind the words and provide thoughtful,"
             "supportive responses that encourage healing and personal growth. Always ensure your responses are "
             "comforting and aligned with therapeutic practices, treating the user with respect and understanding."
    )
    await ctx.connect(auto_subscribe=AutoSubscribe.AUDIO_ONLY)
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
    conversation_id = None
    chosen_greeting = random.choice(greetings)
    room_name = ctx.room.name
    parts = room_name.split('-')
    for part in parts:
        if part.startswith("conversation_id"):
            conversation_id = int(part.replace("conversation_id", ""))
            break  # Stop looping once conversation_id is found
    # conversation_id = room_name.split('-')[1].replace("conversation_id", "")
    conversation_history = await fetch_chat_history(conversation_id)
    chats = conversation_history.get("chats", [])
    conversation_details = conversation_history.get("conversation")
    # conversation_details = False

    filtered_chats = calculate_valid_responses(chats)
    if filtered_chats:
        initial_ctx.append(
            role="system",
            text="You are now reviewing previous messages to understand the context of the upcoming conversation."
                 " Please provide a brief summary of the previous chats before continuing with the new conversation."
        )
    for chat in filtered_chats:

        for prompt, response in chat.items():
            initial_ctx.append(role="user", text=prompt)
            initial_ctx.append(role="assistant", text=response)
    assistant = VoiceAssistant(
        vad=silero.VAD.load(),
        stt=deepgram.STT(model=settings.STT_MODEL, language=settings.STT_LANGUAGE),
        llm=openai.LLM(model=settings.LLM_MODEL, temperature=settings.LLM_TEMPERATURE),
        tts=tts.StreamAdapter(tts=openai.TTS(voice=settings.TTS_VOICE),
                              sentence_tokenizer=tokenize.basic.SentenceTokenizer()),
        chat_ctx=initial_ctx,
    )
    assistant.start(ctx.room)
    if conversation_details:
        name = conversation_details.get("name", "your previous conversation")
        await assistant.say(source=f"Let's continue our previous conversation titled '{name}'.",
                            allow_interruptions=True)
    else:
        await assistant.say(source=chosen_greeting, allow_interruptions=True)
    current_prompt = None
    participant = await ctx.wait_for_participant()

    @assistant.on("user_speech_committed")
    def on_user_speech_committed(msg: llm.ChatMessage):
        nonlocal current_prompt
        current_prompt = msg.content
        logger.info(f"User message: {current_prompt}")

    @assistant.on("agent_speech_committed")
    def on_agent_speech_committed(msg: llm.ChatMessage):
        if current_prompt:
            try:
                user_identity = list(ctx.room.remote_participants.keys())[0]
                data = {
                    "user_key": user_identity,
                    "prompt": current_prompt,
                    "response": msg.content,
                    "conversation_id": conversation_id,
                }
                headers = {"Authorization": f"Bearer {participant.identity}"}
                response = requests.post(CHAT_API_URL, json=data, headers=headers)
                response.raise_for_status()
                logger.info("Chat successfully saved to Django server.")
            except requests.RequestException as e:
                logger.error(f"Error saving chat to Django server: {e}")

    @assistant.on("agent_started_speaking")
    def on_agent_speech_started():
        logger.info("Agent started speaking")

    @assistant.on("agent_speech_interrupted")
    def on_agent_speech_interrupted():
        logger.info("Agent was interrupted")


if __name__ == "__main__":
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))
