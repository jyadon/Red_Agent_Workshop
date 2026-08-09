import asyncio
import json
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# --- Configuration ---
LM_STUDIO_URL = "http://192.168.1.100:1234/v1"  # Host Mac IP address
MODEL_NAME = "qwen3.5-27b"

SERVER_SCRIPT = "/home/kali/Red_Agent/kali-mcp/server.py"

client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")

async def run_agent():
    server_params = StdioServerParameters(
        command="python3",
        args=[SERVER_SCRIPT]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            mcp_tools = await session.list_tools()
            
            tools = [{
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema
                }
            } for t in mcp_tools.tools]

            print(f"[*] Recognized {len(tools)} tools. Querying Qwen3.5...")

            prompt = "List all files in the current directory and show the hostname."
            
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                tools=tools
            )

            # Execute the tool the LLM chose
            tool_call = response.choices[0].message.tool_calls[0]
            if tool_call:
                name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                print(f"[LLM instruction] {name}({args})")

                result = await session.call_tool(name, args)
                print(f"[Execution result]\n{result.content}")

if __name__ == "__main__":
    asyncio.run(run_agent())
