# -*- coding: utf-8 -*-
import json
import logging
import os
from GhidraCopilot.utils import send_https_request
from __main__ import askChoice





def send_prompt_to_llm(prompt_messages, schema=None):
    model = MODEL["name"]
    temperature = MODEL["temperature"]
    max_tokens = MODEL["max_tokens"]

    if model.startswith("claude"):
        return anthropic_request(prompt_messages, temperature, max_tokens, model)
    elif model.startswith("gemini"):
        return gemini_request(prompt_messages, temperature, max_tokens, model, schema)
    else:
        return openai_request(prompt_messages, temperature, max_tokens, model)


def get_model():
    models = {
        "gpt-4.1": {"max_tokens": 30 - 768, "temperature": 1},
        "claude-sonnet-4-20250514": {"max_tokens": 20000, "temperature": 1},
        "gemini-2.5-flash-lite-preview-06-17": {"max_tokens": 200000, "temperature": 1},
    }
    model_names = list(models.keys())
    selected_model = askChoice("Model", "Please choose a language model to use", model_names, model_names[0])
    return {'name': selected_model, 'max_tokens': models[selected_model]['max_tokens'], 'temperature': models[selected_model]['temperature']}

MODEL = get_model()

def get_api_key():
    vendor = "OPENAI"
    if MODEL["name"].startswith("claude"):
        vendor = "ANTHROPIC"
    elif MODEL["name"].startswith("gemini"):
        vendor = "GOOGLE"

    try:
        return os.environ[vendor + "_API_KEY"]
    except KeyError:
        home = os.environ["HOME"]
        keyfile = ".{}_api_key".format(vendor.lower())
        try:
            with open(os.path.join(home, keyfile)) as f:
                return f.readline().strip()
        except IOError:
            logging.error(("Could not find an API key. Please set the {}_API_KEY environment variable "
                           "or create a file at {} with your key.").format(vendor, os.path.join(home, keyfile)))
            exit(1)

def build_prompt(system_message, first_prompt, first_answer, code, items_to_rename, items_key):
    system_msg = {"role": "system", "content": system_message}
    first_prompt_msg = {"role": "user", "content": first_prompt}
    first_answer_msg = {"role": "assistant", "content": first_answer}
    prompt = "### CODE ###\n" + code + "\n### " + items_key + " ###\n" + json.dumps(items_to_rename)
    prompt_msg = {"role": "user", "content": prompt}
    return [system_msg, first_prompt_msg, first_answer_msg, prompt_msg]



def openai_request(prompt, temperature, max_tokens, model):
    data = {"model": model, "messages": prompt, "max_tokens": max_tokens, "temperature": temperature}
    host = "api.openai.com"
    path = "/v1/chat/completions"
    headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(get_api_key())}
    res = send_https_request(host, path, data, headers)
    if res is None or 'error' in res:
        logging.error("OpenAI request failed: {}".format(res))
        return None
    return res['choices'][0]['message']['content'].strip()


def anthropic_request(prompt, temperature, max_tokens, model):
    host = "api.anthropic.com"
    path = "/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": get_api_key(),
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "max-tokens-3-5-sonnet-2024-07-15",
    }
    data = {"model": model, "max_tokens": max_tokens, "temperature": temperature, "system": prompt[0]['content'], "messages": prompt[1:]}
    res = send_https_request(host, path, data, headers)
    if res is None or 'error' in res:
        logging.error("Anthropic request failed: {}".format(res))
        return None
    return res['content'][0]['text'].strip()


def gemini_request(prompt, temperature, max_tokens, model, schema=None):
    host = "generativelanguage.googleapis.com"
    path = "/v1beta/models/{}:generateContent".format(model)
    headers = {"Content-Type": "application/json", "x-goog-api-key": get_api_key()}

    system_instruction = {"parts": [{"text": prompt[0]['content']}]} if prompt and prompt[0]['role'] == 'system' else None
    contents = [{'role': 'model' if msg['role'] == 'assistant' else 'user', 'parts': [{'text': msg['content']}]} for msg in (prompt[1:] if system_instruction else prompt)]

    data = {"contents": contents, "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}}
    if system_instruction:
        data["systemInstruction"] = system_instruction
    if schema:
        data["generationConfig"]["response_mime_type"] = "application/json"
        data["generationConfig"]["response_schema"] = schema

    res = send_https_request(host, path, data, headers)
    if res is None or 'error' in res or not res.get('candidates'):
        logging.error("Gemini request failed: {}".format(res))
        return None

    response_text = res['candidates'][0]['content']['parts'][0]['text']
    if schema:
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            logging.error("Gemini returned invalid JSON: {}".format(response_text))
            return response_text
    return response_text
