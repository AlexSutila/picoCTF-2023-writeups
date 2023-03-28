# No way out

I will be completing this challenge on windows using game cheat techniques because they are fun.

## Looking at what was given

Upon downloading the zip file from the site, we get a folder with an executable inside. The screenshot below shows the first thing I was presented with upon running it (aside from windows telling me it was a virus lol).

![image](https://user-images.githubusercontent.com/96510931/228135759-1c80ce79-5a90-488a-b8ee-e935d0c98503.png)

It is pretty apparent where I'm supposed to go, however I am not immediately able to climb the ladder. The name of the challenge is beginning to make sense:

![image](https://user-images.githubusercontent.com/96510931/228136057-45b4f8d6-cc28-4f46-b5ee-c66b5f761b0f.png)

## The approach

Despite this being a reverse engineering challenge, I believe I can do this without even opening a decompiler or trying to understand the binary. Instead, I decided to use my knowledge of cheating in games to attempt a very primitive teleportation cheat.

### Cheat-engine

Cheat engine does a bunch of stuff, but for this challenge I will be using it to search for the player's position values in memory and modify them during runtime allowing me to, ideally, teleport straight through the wall.

I've never used Cheat engine on Mac, but there is supposedly Mac support: https://www.cheatengine.org/downloads.php

Attaching the process to cheat engine is very simple. Once we do this we will be able to gather a set of memory addresses and narrow down on them as they change. Here is a screenshot of me attaching the game to Cheat-engine:

![image](https://user-images.githubusercontent.com/96510931/228137112-e76fce78-c85f-4d10-a142-cc778b365172.png)

## The exploitation begins

As mentioned earlier, I want to find some sort of position value in memory and change it to achieve teleportation. However, I do not know what the exact values are of the players position or what types they are. However, I can make a reasonable assumption that the X, Y and Z values of my player are likely implemented as floats. I can begin my memory scanning without knowing the starting value. Here is my configuration for the first scan:

![image](https://user-images.githubusercontent.com/96510931/228137673-28e384de-16da-4a9e-b7d4-27fa60fcadde.png)

After hitting the first scan button, you can see the set of addresses it's gathered is quite large. But there are things I can do to narrow my search.

![image](https://user-images.githubusercontent.com/96510931/228137872-2b38a759-279c-4f4e-9192-ae4b3c26a927.png)

I can make a reasonable assumption that the map most likely wasn't massive and that the player was probably placed somewhere near the center:

![image](https://user-images.githubusercontent.com/96510931/228138092-596f7977-f152-450b-ab49-a51b4e3a06fa.png)

But this didn't really help much. The way I can really start narrowing down on the search is by incrementing one of my positional values by a small amount and then searching for values that incremented. When I cannot walk forward anymore, I will do the same but walking backwards and scanning for decreasing values. Which way is positive? Your guess is as good as mine as this approach is all about guess work. My first assumption was that posative was straight forward, because I could imagine the author of the game didn't really have a reason to rotate the character in any particular direction unless they wanted to throw people making this assumption off. I begin by will walking to the position you can see in the screenshot below, scanning for changed values, and then scanning for increased values every time I walk a little bit forward:

NOTE: An occasional moment of standing still and scanning for unchanged values can also help a bit as well.

![image](https://user-images.githubusercontent.com/96510931/228138551-43c8f7f1-72ca-4129-b444-85feea83848e.png)

My first step forward followed by an increased value scan already brought it down to just over seven million:

![image](https://user-images.githubusercontent.com/96510931/228138860-b99e0c88-1099-48a3-a351-ff576e605ea2.png)

## After walking back and forth for a while ...

I was able to narrow down the search to 304 results. Not bad:

![image](https://user-images.githubusercontent.com/96510931/228139482-2edfbf98-01e2-4997-82f6-c1772e1af1f6.png)

Still, 304 is a lot and I don't want to test each one individually, so instead I can bring all of these addresses down into the table below where I can control them. What I typically like doing is locking half
the results I find and trying to move around (locking a value will prevent it from changing). If I locked the correct value, I won't be able to walk. With this method you can sort of perform a binary search to narrow down the results pretty quickly. I ended getting this effect when locking the first half of the results I gathered. Here is what that looked like:

https://user-images.githubusercontent.com/96510931/228140333-4bd5dc38-b8f6-41df-a0c3-042fe81a22cf.mp4

You have to be careful tinkering with some of these values. It will require some trial and error, as I ended up clipping myself through the map at one point:

![image](https://user-images.githubusercontent.com/96510931/228142846-b275229b-3bb2-4c32-b1d1-c31da331c1a5.png)

There is not really any recovering from this, if this happens you get to start over. If you are REALLY not careful you could easily crash the entire game (yes, it's quite frustrating).

## After some trial and error ...

I was finally able to determine that the wall behind me in the video was in between -12 and -5, and I used those values to greatly narrow down my search. I ended up with 38 values, and locking them and setting them to -13 teleported me outside of the wall. Once you are out, you can unlock the values and move around freely:

![image](https://user-images.githubusercontent.com/96510931/228148032-3a6b8a4e-d9c4-4d6c-9bb6-26bbd679c35d.png)

You can get the flag by walking closer to the large while flag pole:

![image](https://user-images.githubusercontent.com/96510931/228148111-26dfa0f4-f462-474c-b145-a9a9f1475ef6.png)

gg2ez
