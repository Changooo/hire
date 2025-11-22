import asyncio
from openai import AsyncOpenAI
import smtplib
from email.mime.text import MIMEText
import json
import sys
import decrypt


MYPASSWD = "REDACTED_FOR_SAFETY"
email = "cgl1234321@gmail.com"
apikey = decrypt.load_api_key(MYPASSWD, infile="openaiapi.bin")
gmailpw = decrypt.load_api_key(MYPASSWD, infile="gmailapppw.bin")

# email = ""
# apikey = ""
# gmailpw = ""

client = AsyncOpenAI(api_key=apikey)

# ======================================================
#  Gmail tools
# ======================================================
SMTP_EMAIL = email
SMTP_PASSWORD = gmailpw

async def send_email(recipient: str, subject: str, body: str) -> str:
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = recipient

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return f"Email successfully sent to {recipient}"
    except Exception as e:
        return f"Failed to send email: {str(e)}"


# ======================================================
#  File tools
# ======================================================
async def read_file(path: str) -> str:
    import os
    try:
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            return f"Error: File does not exist: {abs_path}"
        if not os.access(abs_path, os.R_OK):
            return f"Error: No read permission for file: {abs_path}"

        with open(abs_path, "r") as f:
            data = f.read()
        return f"Contents of {abs_path}:\n{data}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


async def write_file(path: str, data: str) -> str:
    import os
    try:
        abs_path = os.path.abspath(path)
        dir_path = os.path.dirname(abs_path)

        # Create directory if it doesn't exist
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

        # Check if we can write to the directory
        if not os.access(dir_path if dir_path else ".", os.W_OK):
            return f"Error: No write permission for directory: {dir_path}"

        with open(abs_path, "w") as f:
            f.write(data)
        return f"{abs_path} has been written."
    except Exception as e:
        return f"Error writing file: {str(e)}"



# ======================================================
#  Stop tools
# ======================================================
async def stop(reason: str) -> str:
    return f"Conversation stopped: {reason}"
    

# ======================================================
#  Tool schemas
# ======================================================
tools = [
    {
        "type": "function",
        "name": "read_file",
        "description": "Read a local file",
        "parameters": {
            "type": "object",
            "strict": True,
            "properties": {
                "path":{
                    "type": "string",
                    "description": "file path to read"
                }
            },
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "write_file",
        "description": "Write data to a local file",
        "parameters": {
            "type": "object",
            "strict": True,
            "properties": {
                "path":{
                    "type": "string",
                    "description": "file path to write"
                },
                "data":{
                    "type": "string",
                    "description": "data to write to the file"
                }
            },
            "required": ["path", "data"],
        },
    },
    {
        "type": "function",
        "name": "send_email",
        "description": "Send email via Gmail SMTP",
        "parameters": {
            "type": "object",
            "strict": True,
            "properties": {
                "recipient":{
                    "type": "string",
                    "description": "email recipient"
                },
                "subject":{
                    "type": "string",
                    "description": "email subject"
                },
                "body":{
                    "type": "string",
                    "description": "email body"
                }
            },
            "required": ["recipient", "subject", "body"],
        }
    },
    {
        "type": "function",
        "name": "stop",
        "description": "stop the conversation",
        "parameters": {
            "type": "object",
            "strict": True,
            "properties": {
                "reason":{
                    "type": "string",
                    "description": "reason for stopping the conversation"
                }
            },
            "required": ["reason"],
        }
    }
]
 


# ======================================================
#  Tool dispatcher
# ======================================================
async def dispatch_tool_call(tool_call):
    name = tool_call.name
    args = json.loads(tool_call.arguments)

    if name == "read_file":
        return await read_file(**args)

    elif name == "write_file":
        return await write_file(**args)

    elif name == "send_email":
        return await send_email(**args)

    elif name == "stop":
        return await stop(**args)

    else:
        return f"Unknown tool {name}"


# ======================================================
#  Agent loop
# ======================================================
MAX_TURNS = 3
async def run_agent(user_message: str):
    turns = 0 
    messages = [
        {"role": "developer", "content": "If you have done your task, or you do not have to call any tool, use the stop tool to end the conversation."},
        {"role": "user", "content": user_message}
    ]

    while MAX_TURNS > turns:
        response = await client.responses.create(
            model="gpt-4.1",
            input=messages,
            tools=tools,
        )

        messages += response.output
        for o in response.output:
            if o.type == "function_call":
                result = await dispatch_tool_call(o)
                if o.name == "stop":
                    return result
                messages.append({"type": "function_call_output", "call_id": o.call_id, "output": result})
                print(f"[|=|=|] Tool {o.name} called with arguments {o.arguments}")
            
            elif o.type == "message":
                print("[^__^] Assistant:", o.content[0].text)

            else:
                raise RuntimeError("Unexpected response type:", o.type)

        turns += 1
    
    return "Max turns reached."

# ======================================================
#  Main
# ======================================================
async def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py '<your message>'")
        return
    message = sys.argv[1]
    result = await run_agent(message)
    print("\n=== FINAL OUTPUT ===")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
