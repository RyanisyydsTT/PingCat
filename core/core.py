import asyncio
import logging
import os
import socket
import sys

import aiodns
import arc
import hikari
import httpx
import validators

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

bot = hikari.GatewayBot(os.environ["TOKEN"])
arc_client = arc.GatewayClient(bot)
httpx_client = httpx.AsyncClient()
logger: logging.Logger = logging.getLogger("PingCat")

hosts = [
    "Taipei, Taiwan - AS149791 StarVerse Network Ltd.",
    "Taichung, Taiwan - AS17809 VEE TIME CORP.",
    "Taoyuan, Taiwan - AS131596 TBC",
]


async def identify_ip(ip_address: str):
    resolver = aiodns.DNSResolver()
    if validators.ip_address._check_private_ip(ip_address, is_private=True):
        return "private", ip_address

    if validators.ipv4(ip_address):
        return "ipv4", ip_address

    if validators.ipv6(ip_address):
        return "ipv6", ip_address

    if validators.domain(ip_address):
        result = await resolver.gethostbyname(ip_address, socket.AF_INET)
        return "ipv4", result.addresses[0]

    return "invalid", ip_address


async def ping_host(
    ctx: arc.GatewayContext,
    url: str,
    api_key: str,
    target: str,
    ip_version: str,
    host: str,
    private: bool,
) -> arc.InteractionResponse:
    data = {
        "target_ip": target,
        "ip_version": ip_version,
        "api_key": api_key,
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=data)
            response.raise_for_status()
            json_response = response.json()
        except httpx.TimeoutException:
            # `::` always timeout for some reason, shouldn't it return non-success?
            return await ctx.respond(
                "Error: Timeout while attempting to ping the IP address. Please check if the entered IP address is correct.",
            )
        except httpx.HTTPStatusError as e:
            logger.exception(e)
            json_response = response.json()
            if private:
                result = json_response.get("output", "Unknown error occurred.").replace(url, "[HIDDEN]")
            else:
                result = json_response.get("output", "Unknown error occurred.")
            return await ctx.respond(result)
        except Exception as e:
            logger.exception(e)
            json_response = response.json()
            if private:
                result = json_response.get("output", "Unknown error occurred.").replace(url, "[HIDDEN]")
            else:
                result = json_response.get("output", "Unknown error occurred.")
            return await ctx.respond(result)

        logger.info(
            f"{'=' * 30}\nStatus Code: {response.status_code}\nResponse Content: {response.json()}\n{'=' * 30}\n",
        )

        if json_response.get("success"):
            formatted_response = (
                f"Ping result from `{host}`\n```\n{json_response.get('output')}\n```"
            ).replace(url, "[HIDDEN]")
            return await ctx.respond(formatted_response)

        return await ctx.respond(json_response.get("output", "Unknown error occurred."))


@arc_client.include
@arc.slash_command("ping", "Ping test!")
async def handle_ping_command(
    ctx: arc.GatewayContext,
    target: arc.Option[str, arc.StrParams("Which IP or domain do you want to ping?")],
    host: arc.Option[
        str,
        arc.StrParams(
            "Which host do you want to ping from?",
            choices=hosts,
        ),
    ],
) -> arc.InteractionResponse:
    ip_version, detected_target = await identify_ip(target)

    if ip_version == "invalid":
        return await ctx.respond("Invalid IP address or domain name.")

    if ip_version == "private":
        return await ctx.respond("Private IP addresses are not allowed.")

    host_info = {
        "Taipei, Taiwan - AS149791 StarVerse Network Ltd.": {
            "url": os.environ["IP1"],
            "api_key": os.environ["APIKEY1"],
            "private": True,
        },
        "Taichung, Taiwan - AS17809 VEE TIME CORP.": {
            "url": "https://api.cowgl.xyz/ping",
            "api_key": "",
            "private": False,
        },
        "Taoyuan, Taiwan - AS131596 TBC": {
            "url": "https://pingapi.milkteamc.org/ping",
            "api_key": "",
            "private": False,
        },
    }

    if host not in host_info:
        return await ctx.respond("Host not supported yet.")

    url = host_info[host]["url"]
    api_key = host_info[host]["api_key"]
    is_private = host_info[host]["private"]

    return await ping_host(ctx, url, api_key, detected_target, ip_version, host, is_private)
