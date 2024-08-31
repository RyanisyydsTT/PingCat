import ipaddress
import logging
import os
import socket

import arc
import hikari
import httpx
import validators

bot = hikari.GatewayBot(os.environ["TOKEN"])
arc_client = arc.GatewayClient(bot)
httpx_client = httpx.AsyncClient()
logger: logging.Logger = logging.getLogger("PingCat")

hosts = [
    "Taipei, Taiwan - AS149791 StarVerse Network Ltd.",
    "Taichung, Taiwan - AS17809 VEE TIME CORP.",
    "Taoyuan, Taiwan - AS131596 TBC",
    "Tainan, Taiwan - AS3462 Data Communication Business Group",
]


def domain_to_ip(
    domain: str,
):
    try:
        ip_address: str = socket.gethostbyname(domain)
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
            ip_address,
        )
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "ipv4", ip_address
        return "ipv6", ip_address
    except socket.gaierror:
        logger.exception("Failed to resolve domain")
        return "invalid", domain
    except ValueError:
        logger.exception("Invalid IP address")
        return "invalid", domain


def identify_ip(input_str: str):
    if validators.ipv4(input_str):
        return "ipv4", input_str
    if validators.ipv6(input_str):
        return "ipv6", input_str
    if validators.domain(input_str):
        ip = domain_to_ip(input_str)
        return "domain", ip
    return "invalid", input_str


async def ping_host(
    ctx: arc.GatewayContext,
    url: str,
    api_key: str,
    target: str,
    ip_version: str,
    host: str,
) -> arc.InteractionResponse:
    data: dict[str, str] = {
        "target_ip": target,
        "ip_version": ip_version,
    }
    if not api_key:
        data.update({"api_key": ""})

    try:
        response: httpx.Response = await httpx_client.post(url, json=data)
        response.raise_for_status()
        logger.debug(
            f"{'=' * 30}\nStatus Code: {response.status_code}\nResponse Content: {response.text}\n{'=' * 30}\n",
        )

        if not response.text:
            logger.exception(f"Received an empty response from the server: {response}")
            return await ctx.respond(
                "Error: Received an empty response from the server.",
            )

        json_response = response.json()
        formatted_response = (
            f"Ping result from `{host}`\n```\n{json_response.get('output')}\n```"
        )
        return await ctx.respond(formatted_response)
    except httpx.TimeoutException as e:
        logger.exception(f"Failed to get response from server: {e}")
        return await ctx.respond(
            "Timeout while attempting to ping the IP address. Please check if the entered IP address is correct.",
        )
    except Exception as e:
        logger.exception(f"Failed to parse JSON response: {e}")
        return await ctx.respond(
            f"Error: Unable to parse JSON response. Raw response:\n```\n{response.text}\n```",
        )


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
    ip_version, detected_target = identify_ip(target)

    if ip_version == "invalid":
        return await ctx.respond("Invalid IP address or domain name.")

    try:
        host_index = hosts.index(host)
    except ValueError:
        return await ctx.respond("Host not supported yet.")

    api_key = None

    if host_index == 0:
        url: str = os.environ["IP1"]
        api_key: str = os.environ["APIKEY1"]
    elif host_index == 1:
        url = "https://api.cowgl.xyz/ping"
    elif host_index == 2:
        url = "https://pingapi.milkteamc.org/ping"
    elif host_index == 3:
        url = "http://59.127.149.67:9199/ping"

    return await ping_host(ctx, url, api_key, detected_target, ip_version, host)
