import asyncio
from openai import AsyncOpenAI
import smtplib
from email.mime.text import MIMEText
import json

client = AsyncOpenAI(api_key=


"sk-pr

oj-

Ft2KiCoq1dE-QDloHfHX7q5JQqYt2eB9hXXk
7O98Eqq-ms_o5irMai64TjOe
JzsSScWGqsx0GIT3BlbkFJkz3mY
TR5jsZa31juMJYB



j4acbHxvQflWmFSl_dxgL


iGAEYsMlB4icW70wz9MVhpSo1ZUzj")


# ======================================================
#  SMTP 실제 구현
# ======================================================
SMTP_EMAIL = "cgl1234321@gmail.com"
SMTP_PASSWORD = "lkmuuuswveqhcb"   # 주의: 앱 비밀번호 필요


async def send_email(recipient: str, subject: str, body: str) -> str:
    """Gmail SMTP 실제 구현."""
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
    try:
        with open(path, "r") as f:
            data = f.read()
        return f"Contents of {path}:\n{data}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


async def write_file(path: str, data: str) -> str:
    try:
        with open(path, "w") as f:
            f.write(data)
        return f"{path} has been written."
    except Exception as e:
        return f"Error writing file: {str(e)}"



# ======================================================
#  Stop tools
# ======================================================
async def stop(reason: str) -> str:
    return f"Conversation stopped: {reason}"
    

# ======================================================
#  Tool schemas (공식 beta.responses 방식)
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
#  Agent 실행 루프 (공식 beta)
# ======================================================
MAX_TURNS = 3
async def run_agent(user_message: str):
    turns = 0 
    messages = [
        {"role": "developer", "content": "If you have done your task, use the stop tool to end the conversation."},
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
                print(f"✅ Tool {o.name} called with arguments {o.arguments}")
            
            elif o.type == "message":
                print("✅ Assistant:", o.content[0].text)

            else:
                raise RuntimeError("Unexpected response type:", o.type)

        turns += 1
    
    return "Max turns reached."

# ======================================================
#  실행 예시
# ======================================================
async def main():
    message = "/data1/changoo/agent/README.md 에 애국가 써줘."
    # message = (
    #     "send_email 기능 테스트할게. "
    #     "recipient: cgl1234321@gmail.com, subject: 'hi', body: 'hello!' "
    #     "이메일 보내줘."
    # )
    # message = "just stop the conversation now."
    result = await run_agent(message)
    print("\n=== FINAL OUTPUT ===")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
