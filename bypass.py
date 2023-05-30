import re
import dukpy
import requests
import aiohttp
from aiohttp_socks import ProxyType, ProxyConnector, ChainProxyConnector

_0xfab6 = [
    "\x70\x75\x73\x68",
    "\x72\x65\x70\x6C\x61\x63\x65",
    "\x6C\x65\x6E\x67\x74\x68",
    "\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72",
    "",
    "\x30",
    "\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65",
    "29515dbe13665e7d34a972e331ab60db",
    "bddde53c711747e7b6d4b28f3d40a830",
    "17e8f46597b7451d11d3568497a053c4",
    "\x63\x6F\x6F\x6B\x69\x65",
    "\x52\x33\x41\x43\x54\x4C\x41\x42\x2D\x41\x52\x5A\x31\x3D",
    "\x64\x65\x63\x72\x79\x70\x74",
    "\x3B\x20\x65\x78\x70\x69\x72\x65\x73\x3D\x54\x68\x75\x2C\x20\x33\x31\x2D\x44\x65\x63\x2D\x33\x37\x20\x32\x33\x3A\x35\x35\x3A\x35\x35\x20\x47\x4D\x54\x3B\x20\x70\x61\x74\x68\x3D\x2F"
]

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.64"


def to_numbers(value):
    return dukpy.evaljs('''
        var _0x9ee6x3 = []; 
        var _0x9ee6x2 = dukpy['value'];
        _0x9ee6x2["replace"](/(..)/g, function (_0x9ee6x2) { 
            _0x9ee6x3["push"](parseInt(_0x9ee6x2, 16)) }); 
            _0x9ee6x3 
    ''', value=value)


def to_hex(value):
    return dukpy.evaljs('''
        _0xd8aa = dukpy['value'][1];
        function toHex() { 
            for (var _0x9ee6x2 = 1 == arguments[_0xd8aa[2]] && arguments[0][_0xd8aa[3]] == Array ? arguments[0] : arguments, _0x9ee6x3 = _0xd8aa[4], _0x9ee6x5 = 0; _0x9ee6x5 < _0x9ee6x2[_0xd8aa[2]]; _0x9ee6x5++) { 
                _0x9ee6x3 += (16 > _0x9ee6x2[_0x9ee6x5] ? _0xd8aa[5] : _0xd8aa[4]) + _0x9ee6x2[_0x9ee6x5].toString(16) 
            }; 
            return _0x9ee6x3["toLowerCase"]() 
        } 
        toHex(dukpy['value'][0])
    ''', value=value)


def slow_aes(value):
    with open("aes.txt", "r") as fp:
        run = " slowAES['decrypt'](dukpy['value'][0], 2, dukpy['value'][1], dukpy['value'][2])"
        data = dukpy.evaljs(fp.read() + run, value=value)
        return data


def bypass(agent=user_agent):
    session = requests.session()
    session.headers = {"user-agent": agent}
    r = session.get("https://forum.arizona-rp.com/", timeout=3)
    codes = r.text.split(",\"\\x30\",\"\\x74\\x6F\\x4C\\x6F\\x77\\x65\\x72\\x43\\x61\\x73\\x65\",")[1].split(",\"\\x63\\x6F\\x6F\\x6B\\x69\\x65\",")[0]
    found = re.compile("\"(.*)\",\"(.*)\",\"(.*)\"").findall(codes)[0]
    a, b, c = to_numbers(found[0]), to_numbers(found[1]), to_numbers(found[2])
    return _0xfab6[11] + to_hex([slow_aes([c, a, b]), _0xfab6]), session.headers.get("user-agent")


async def bypass_async(agent=user_agent, proxy=""):
    body = ""
    if len(proxy) > 1:
        connector = ProxyConnector.from_url(proxy)
        async with aiohttp.ClientSession(connector=connector) as session:
            session.headers.update({"user-agent": agent})
            async with session.get("https://forum.arizona-rp.com/") as resp:
                body = await resp.text()
    else:
        async with aiohttp.ClientSession() as session:
            session.headers.update({"user-agent": agent})
            async with session.get("https://forum.arizona-rp.com/") as resp:
                body = await resp.text()
    
    codes = body.split(",\"\\x30\",\"\\x74\\x6F\\x4C\\x6F\\x77\\x65\\x72\\x43\\x61\\x73\\x65\",")[1].split(",\"\\x63\\x6F\\x6F\\x6B\\x69\\x65\",")[0]
    found = re.compile("\"(.*)\",\"(.*)\",\"(.*)\"").findall(codes)[0]
    a, b, c = to_numbers(found[0]), to_numbers(found[1]), to_numbers(found[2])
    return _0xfab6[11] + to_hex([slow_aes([c, a, b]), _0xfab6]), session.headers.get("user-agent")


def main():
    code = bypass()
    cookies = "name=value; name=value; name=value; "  # Из браузера копируем авторизованные куки без куки react lab arz
    cookies += code[0]
    r = requests.get("https://forum.arizona-rp.com/account/account-details", headers={"cookie": cookies, "user-agent": code[1]})
    username = re.compile("<span class=\"p-navgroup-linkText username--.*\">(.*)</span>").findall(r.text)
    print(username)


if __name__ == '__main__':
    main()
