---
title: "Day 7 - Jigsaw"
date: 2021-12-19T11:14:23-06:00
---

## Challenge Description

Santa has hidden a secret message on the backside of a jigsaw puzzle that he completed. Sadly, one of his elves dropped the completed puzzle, shuffling all the pieces. Can you verify that it is indeed impossible for the Grinch to recover this message?

[Downloaded File](files/jigsaw_pieces.tar.xz)

## Overview

We are given a bunch of PNGs with jigsaw pieces on them, looking at their metadata we can order them and extract a secret message

## Writeup

We're given a tar file of 667 jigsaw pieces, extracting and taking a look:

```
07-jigsaw > tar xvf jigsaw_pieces.tar.xz
jigsaw_pieces/
jigsaw_pieces/e037a1d80fcfd3155bdbbbcfff210893427316c741fe0f05825a6e14beb9b1e3.png
jigsaw_pieces/9f8e0c2439b835084b048b43e81f25b37c13eb2ad945145af23bc0668eda0b60.png
jigsaw_pieces/dc87fa39086e30bc68c2f11377371f93f38e84b7eaaeef2f255114d733e266a3.png
...
jigsaw_pieces/a5506cd2022a655745a511a3f307ff80afb9ab06cce90857332e8404d1ec3034.png
jigsaw_pieces/6e6b095ce306e4f9ff8b742ae7b99cf4db055c13d0b660903630b810d78e915b.png
07-jigsaw > ls jigsaw_pieces/ | wc -l
667
07-jigsaw > display jigsaw_pieces/8ff2759158202b7b70c48e2e29e3176770e63ff615ede345034b2185226f4b24.png
```

![an example jigsaw piece](images/8ff2759158202b7b70c48e2e29e3176770e63ff615ede345034b2185226f4b24.png)

The description says that Santa hid a message on the back of the jigsaw puzzle, not the front, so putting the pieces together might not work. Instead, lets check the metadata using `exiftool`.

```
07-jigsaw > exiftool jigsaw_pieces/8ff2759158202b7b70c48e2e29e3176770e63ff615ede345034b2185226f4b24.png 
ExifTool Version Number         : 12.30
File Name                       : 8ff2759158202b7b70c48e2e29e3176770e63ff615ede345034b2185226f4b24.png
Directory                       : jigsaw_pieces
File Size                       : 26 KiB
File Modification Date/Time     : 2021:11:19 13:51:52-06:00
File Access Date/Time           : 2021:12:19 11:49:08-06:00
File Inode Change Date/Time     : 2021:12:19 11:47:35-06:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 252
Image Height                    : 199
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Gamma                           : 2.2
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Background Color                : 255 255 255
Comment                         : Secret data: 'ICA'
Image Size                      : 252x199
Megapixels                      : 0.050
```

Ah! Comment section with some "Secret data"! Extracting the secret data from all the files:

```
07-jigsaw > for p in `ls jigsaw_pieces`; do \
                exiftool jigsaw_pieces/$p | \
                sed -n "s/Comment\s*: Secret data: //p" | \
                tr -d "'" | xargs echo $p >> secret-data.txt; done
07-jigsaw > head -5 secret-data.txt
0a7e248c02d2ce19118264c18e0585a6048b7ad1d7c86c5205dd3018155e2afb.png Cl
0a556a4438fcddf03f19ded8153c34dd43445bf78ba3fdae72268c341bebf8a9.png cD
0b7d90c7b9be3e66336d12a4b8bd0ee4e754ba7f308f5d1d71d6332289033aee.png ICA
0b97dcc82b4a4eceecdc4b178e8862b4f04351843c1a6d314438294e498eb61a.png gI
0b7084bb3ddcdeee40d49a494d78fd27835fe4f5cdaea151549993b74bb7c6ae.png GN
07-jigsaw > awk '{print $2}' secret-data.txt | tr -d '\n'
gXFFl9fXgICABpgIfX1CAgICAB3lfICAb2Li4gIgICLyACACAgICICAgI9fAgIZlIFqKi9eXCAX19AgCAcDClGNICAgIlc3ogFwgIC2UgCAICGhX19iAub2MgCAE9PgIFuICAu4gLiAlv8ggIdGICAIgI8L8CifX1uCgagIAgqKFdPV8LICBCAgICICAAgICAAg9frIICgIgICAggIkggIX1LiA3xS4tCAg3xAg9fLiICCAgHwgIGCAgLgICwg0uAg4gCA0uICAgKICAogIICAgICPlAgCAgICuLFwqi4AgiAgICgI8IAgazbXgIAgICogXGkAgICAgIyAUgHxgICgICKiICBICpIgIICAAgIAgICAczoX19Zm9CAggLi0AggICLixfICB8gKfX1CAgCA0KLyogKVuICiAgICAgBTyoKigICCAIC8KIgICogAgi4gIVfCA0uCACAgICtfNzXbmXCBffMjgICAvLgICfD1gICCAgCBgICAgICAIC1I8ICAC8KiAgAgAgI8XgICVsuICICA4gKiAAg9ixftfCAKiCAgFxgIICAvIF8gx8X1Ag4ggLgSAgICAgIgIeXAgLigICAICG98XgIffAgIbHgIAgAggIICAgfX1oq114tfX4tLvbyCAg0ukvIAqLCAAvIiAX1gICgICDIw7UICCAgICgIICqCgICAgi0uX38guLAgLIHfXCAAggICeIwKAqC9BfXICtLfDAgIgIAg4uIAgIuCICACAICgIICYWAgIAgI9fxcHx8Kii0AgCBXyICICACAXiCAgIgICICCAvKyCAICgagIaXX19oqiocIuLwqCB21huICgIgKgIgIICICCiACAgAgCAAgYzAuICAIC9fXAgLCAAgLioqAgIAggICgICICAS4hpX19CAuCgIAgICApcGkAgAgIICBCAljICAgd8guI200Li0CA8X1gILSAgCAxsC4tiAg3BlF9fX1gIgIC4gILiACAgZX04KcnuICi4K98LiAgoZXLSIF4CBS4tC8ICAZnoqXCAD18Ki8CACANFAgCAgKieICgICAgAgICy8CACAvLWICeW9gIqXKigICgICAgCAXA8guCiLigIgI8KCAHxvLyi4gLigICFwS9Li0YSIbICA18ofCICICAICS4AgICAfcGpcaICACAX1ICAwgvIBcpcgIoqK19yAAgIC1ICgICICACAIC50tfI8X3uLCAggIAgZXgfHffLiAAgIC98IuICAgICACAICAICACAVyXCAg0gLygS8CAgCBfICBeIgICCAgICLSCBICAyINfAgIAgSAgICICgLYWcIAgKiogIIC4gICgIgICICICICAgfCAgICAX3xfi4g1tCAgF9AguLAgagLiAgICLQ19fICAT0IC4F98CAgIC4tgINoiBAg8gLiBgIlwrgICAIFw4tuIAgI18N3AgAgICAgILSlIgIuLShbxffC989fuLICAiAAgIAgEF8IgLCAgGJ19ICA4uLCAgICgICAgS8vCBcyBbGQgy8gIMWdXGIC1cfXAgIqIgK8gLoqgICCAgeICkgIFioICvLWIC
```

Looks like it's a bunch of alphanumeric characters. I wonder if it's base64? If we try to decode it, it gives us a bunch of garbage:

```
07-jigsaw > awk '{print $2}' secret-data.txt | tr -d '\n' | base64 -d
qE×}}Bå|obââ  "ò    #×Àe ZõÍè\  hW×؀¹½ ôâî . %¿È ! #Âü
'×Öà j=~²|,
.ù@   + 7Å7=|  .Â

...
```

Though that could just be because they aren't in the right order. Can we use some other piece of metadata to put the pieces in order? Lets check what pieces of metadata are different between two pieces

```
07-jigsaw > diff <(exiftool jigsaw_pieces/8ff*.png) <(exiftool jigsaw_pieces/8ef*.png)
2c2
< File Name                       : 8ff2759158202b7b70c48e2e29e3176770e63ff615ede345034b2185226f4b24.png
---
> File Name                       : 8ef80331ff8abbecefc679fc8564de7cac18d9d2d2158695bddc48f4596a6f36.png
4,7c4,7
< File Size                       : 26 KiB
< File Modification Date/Time     : 2021:11:19 13:51:52-06:00
< File Access Date/Time           : 2021:12:19 17:17:16-06:00
< File Inode Change Date/Time     : 2021:12:19 17:17:16-06:00
---
> File Size                       : 32 KiB
> File Modification Date/Time     : 2021:11:19 14:01:30-06:00
> File Access Date/Time           : 2021:12:19 17:17:17-06:00
> File Inode Change Date/Time     : 2021:12:19 17:17:17-06:00
12,13c12,13
< Image Width                     : 252
< Image Height                    : 199
---
> Image Width                     : 189
> Image Height                    : 282
29,31c29,31
< Comment                         : Secret data: 'ICA'
< Image Size                      : 252x199
< Megapixels                      : 0.050
---
> Comment                         : Secret data: 'Ag'
> Image Size                      : 189x282
> Megapixels                      : 0.053
```

The file modification time looks like a good way to order the piece's secret data. Lets try it and base64 the result:

```
07-jigsaw > for p in `ls jigsaw_pieces`; do \
                exiftool -d "%s" jigsaw_pieces/$p | \
                sed -n "s/File Modification Date\/Time\s*: //p" | \
                xargs -I % echo % $p >> mod-time.txt ; done
07-jigsaw > head -5 mod-time.txt
1637351551 00168226de721bf30d62a60a2a34b4074a8c5d70d5ccd7cbfcc35b2a0a071e75.png
1637351840 001cd7fd3b2c4db7f7c52af6242bc18e8e16d65d7e1eebb52506b838c4b30ca4.png
1637352450 0058a0eb229f3b028da843249197e2f4d9758e2aa65221d093a76355ded4ac8f.png
1637351883 0075574eef637e2b0cb7df80aa6eb6432ac1e02d298545a860158913c670f55e.png
1637351789 009822fbd80912f7b6f2f07de67b1e806395fa462a9fbd69fe84f7290fec5851.png
07-jigsaw > join -o "1.1 1.2 2.2" -1 2 -2 1 mod-time.txt secret-data.txt | sort -n | head -5
1637351333 8cbb7a19bb61692f38fbc6ef215e3534efdcf70d1f7a5033e1113aabfe394c60.png IC
1637351334 605df812aef157a39942d05476c309b9f5a21546e0ac080c59034ee9481a7a7f.png 4g
1637351336 a631c60b64153d27dc626066c2f2e002bda90914ef57a96d0dca6b6d6f2d5381.png ICA
1637351337 f5f67ca6871a12fd8b0866127514a778b196e3773cba9ac56caa9cba0c1dcbbe.png gI
1637351339 71522184211f3e4307df7d7f048ece0dd407d018c53b975356a8d02e333eed4f.png CAg
07-jigsaw > join -o "1.1 1.2 2.2" -1 2 -2 1 mod-time.txt secret-data.txt | \
                 sort -n | awk '{print $3}' | tr -d '\n' | base64 -d
 .       .        _+_        .                  .             .
                  /|\
       .           *     .       .            .                   .
.                i/|\i                                   .               .
      .    .     // \\*              Santa wishes everyone all
                */( )\\      .           the best for 2022       .
        .      i/*/ \ \i             ***************************
 .             / /* *\+\             Hopefully you can use this:   .
      .       */// + \*\\*       AOTW{Sm4ll_p1ec3s_mak3_4_b1g_pic7ure}       .
             i/  /^  ^\  \i    .               ... . ...
.        .   / /+/ ()^ *\ \                 ........ .
            i//*/_^- -  \*\i              ...  ..  ..               .
    .       / // * ^ \ * \ \             ..
          i/ /*  ^  * ^ + \ \i          ..     ___            _________
          / / // / | \ \  \ *\         >U___^_[[_]|  ______  |_|_|_|_|_|
   ____(|)____    |||                  [__________|=|______|=|_|_|_|_|_|=
  |_____|_____|   |||                   oo OOOO oo   oo  oo   o-o   o-o
 -|     |     |-.-|||.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-
  |_____|_____|
```

## Final Notes: 

I stopped doing the Advent of Code to spend more time on Advent Over the Wire CTF, so when I saw this challenge, I thought it was a straightforward programming challenge. I spent too long trying to fingerprint each of the jigsaw piece sides (I called the two types of jigsaw piece edges "tabs" and "spaces"). After a day of programming wasted, a CTF friend mentioned the metadata and things fell into place much faster. Great starter challenge, seeing the beautiful ASCII art after a bunch of garbage felt very good.