# Horsetrack

Before I begin, I will mention that I was only able to pop a shell locally for reasons beyond me. Regardless, I still
found the solution I came up with to do this much locally interesting and I enjoyed coming up with it so I wanted to
share anyway :)

## Looking at the binary and inital guess work

At first glance, the binary appears to give us four options:

![image](https://user-images.githubusercontent.com/96510931/228019847-3336d337-0613-4888-94da-6ea7c50e8bfc.png)

Option 1 asks for a stable index and name length between 16 and 256 characters, then prompts the user for a name.
This automatically feels like it might do some sort of heap allocation of which we may be able to abuse if we can
tinker with the memory after the allocations made are freed. 

![image](https://user-images.githubusercontent.com/96510931/228020932-7c3974c2-dbb7-4443-b0c1-8ee53d9ac562.png)

Option 2 just asks for a stable index to specify which horse to remove. This likely frees the memory allocated
in option one. Of course, these are still just assumptions for the time being, I will further inspect these options
using reverse engineering tools to confirm my suspicions.

![image](https://user-images.githubusercontent.com/96510931/228021509-b15de5eb-799e-4023-8a2e-6a26ceabfcac.png)


Option 3 allows you to race all the horses you've added, and it will print a fancy little ascii representation of the
horses racing. What ever, the important part here is it prints the name of the winner once the race is over which could
potentially be used to leak information alongside some heap-based vulnerabilities if my earlier suspicions hold up.

![image](https://user-images.githubusercontent.com/96510931/228023291-eea6c627-e968-42e6-ae47-c516bb8ebdce.png)

It is also worth noting that I was unable to race if I had 4 or less horses added.

![image](https://user-images.githubusercontent.com/96510931/228023461-de3e6a41-b808-4a5a-8bd6-2099b895b9f1.png)


Lastly, option 4 should be fairly self explanatory. Not really of much interest to me.


## But wait, there is more ...

Upon further inspection, after downloading the binary and decompiling it in IDA, there appears to be another
secret option which they do not display in the menu prints. The value v5 is the user's answer to the choice prompt,
and as you can see in the image below, there is a case 0 despite an option 0 not being displayed:

![image](https://user-images.githubusercontent.com/96510931/228020421-f9b5b9fc-fb60-4726-affb-34cf285f49d8.png)

Upon giving it a try, I was right. There is a secret option which lets you modify one of the horses. 

![image](https://user-images.githubusercontent.com/96510931/228024759-b82a737a-44ef-4906-a362-0e641949e66f.png)

There is a complication, however. If we try racing after modifying a horse we are unable to race and the program exits.

![image](https://user-images.githubusercontent.com/96510931/228026115-8f9a29bf-73f7-4cc8-8d0f-b1cb8751b064.png)

We will have to find a way around this, but first lets actually make sure that this will infact involve heap exploitation
and see what else we can find by digging around in IDA.


## Reverse engineering

### Option 1: Add horse

I've renamed the function called in case 1 of the switch statement accordingly:

![image](https://user-images.githubusercontent.com/96510931/228028855-9bfa2cbf-71bc-436c-8d5a-b6ede8b03e99.png)

Upon further inspection, they do infact appear to do a malloc like I originally suspsected. As messy as the line with
malloc is, this just appears to be saving the pointer to an array of pointers to each allocation.

![image](https://user-images.githubusercontent.com/96510931/228029017-51227682-0a01-43dc-9d17-e6dba8a650f7.png)

Additionally, they call this sub_401226 function which appears to be reading the name of the horse. Upon further
inspection of this function, it looks like it will stop reading characters from the user when it sees a 0xFF byte.
Note taken. I've renamed this function read_name for readability purposes, see below:

![image](https://user-images.githubusercontent.com/96510931/228030184-78016630-c428-4036-8db4-56e710c4ac19.png)

### Option 2: Remove horse

Like before, I've renamed the function called in case 2 of the switch statement accordingly:

![image](https://user-images.githubusercontent.com/96510931/228030682-6c3f6b2f-d06c-46fe-bd88-97fee510aaaf.png)

Once again, my earlier predictions are correct. This frees the pointer at the index we specify. It is slightly frustrating
that they set the pointer to zero after it is freed as it makes a use-after-free attack on any given allocation slightly
more difficult, but there might be a way around it (spoiler alert there is).

![image](https://user-images.githubusercontent.com/96510931/228030852-1b6650a5-edbb-4f72-b39d-ea0b7acc5dee.png)

## Option 3: Race

Before actually looking into the functions called by race, I want to take a look at case 3 of the switch statement
one more time, as there is a bit more going on.

![image](https://user-images.githubusercontent.com/96510931/228072151-40b961d7-b4f0-411d-a0f6-d62ea34f1100.png)

First of all, we can see that if dword_4040EC is non-zero, we get caught cheating and setting v6 equal to 1 terminates
the forever loop the switch statement is inside of which in turn prevents us from racing (or doing anything else for that
matter).

This dword_4040EC comes from the .bss section as shown below. This is likely what prevents us from racing if we try
to use the secret option to cheat and modify a horse. On the bright side, it shouldn't be too difficult to overwrite
this value once we have arbitrary read write since the binary does not have PIE enabled.

![image](https://user-images.githubusercontent.com/96510931/228072093-50ee2c2b-feda-4f8a-a0f0-32664a4593e4.png)

Next, by looking further into the count_horses, a_horse_has_won, and move_horses functions, all of which I have named accordingly,
we can see that horses are part of the race if the pointer is non-zero. This is slightly problematic for abusing a use-after free
since we observed that remove_horse zeros out the respective pointer when a horse is removed. 

![image](https://user-images.githubusercontent.com/96510931/228072641-cc515ec3-34ce-48b2-a2be-4e47dc82897c.png)
![image](https://user-images.githubusercontent.com/96510931/228072700-c24a54e3-8755-4755-adfd-8e57031242c2.png)
![image](https://user-images.githubusercontent.com/96510931/228072745-2e6d1630-1e17-4015-a78b-5e16d118202a.png)


## Option 0: Cheating

Just like options 1 and 2, I've renamed the function called in case 0 accordingly. It is worth noting that upon taking this
particular code path that the .bss variable which keeps track of whether or not we have cheated is set to one. So in order to
race again, we will have to reset this back to zero via arbitrary read write like mentioned earlier.

![image](https://user-images.githubusercontent.com/96510931/228068273-ffe48b2e-6123-4006-976e-c0926fbee69b.png)

Looks like the cheat function calls the read_name function that was also called in add_horse. Since they also give us a new spot
to place it, we can also un-zero the pointer if it was freed allowing us to actually use the horse in the race. Recall the spoiler
alert I gave when talking about remove_horse, as this is the work around.

![image](https://user-images.githubusercontent.com/96510931/228070309-84e2104d-ef63-4d1d-bc95-19ad37ea5cf4.png)


## The exploitation beings

With all that, we can begin thinking about how we will exploit this. I will be attempting to pop a shell. My high level approach will
consist of:
- Leak the ASLR bits from the heap to cope with the fact that their version of libc has safe linking. Note that we will not be able to
  abuse the cheat option to do this as we do not have arbitrary read write yet to set that .bss variable back to zero.
- Once we have the ASLR bits, we will be able to cope with safe-linking, which will let us cheat and continue to race anyway. We will take
  advantage of this fact to leak an address from LIBC.
- After obtaining the base address of LIBC, we will be able to locate the stack with another leak. I will use this leak to find a return
  pointer we can overwrite with a ROP chain. We should have plenty of gadgets to work with since we should have a LIBC leak.
- Last, overwrite the return pointer and use ROP to pop a shell.

Each of these steps will be explained further in detail below.

### Boilerplace

Just to get the obvious out of the way and keep the script somewhat clean, here is the boilerplate pwntools instantiation of the
process and ELF object, in addition to some functions which we can use to easily pick one of the options given to us by the binary.

```
from pwn import *

p = process('./vuln')
e = ELF('./vuln')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def cheat(index, name, newspot):
┊   p.sendline(b'0')
┊   p.sendline(str(index).encode())
┊   p.sendline(name)
┊   p.sendline(str(newspot).encode())

def add_horse(index, length, name):
┊   p.sendline(b'1')
┊   p.sendline(str(index).encode())
┊   p.sendline(str(length).encode())
┊   p.sendline(name)

def remove_horse(index):
┊   p.sendline(b'2')
┊   p.sendline(str(index).encode())

def race():
┊   p.sendline(b'3')
```

### Coping with safe-linking

In order to obtain arbitrary read-write, we will have to be able to overwrite the next pointer on a freed heap allocation and 
then malloc until we get an allocation pointing to where we specified. However, safe-linking presents a mitigation from doing this by
jumbling the next pointer. If we are to do tcache poisoning, we will have to replicate this pointer jumbling. 

Thankfully, the pointer jumbling is rather simple. It just XORs the pointer with the address of the allocation, shifted
12 bits to the left. In other words, the next pointer is XORed with the random bits from the address of the allocation. 

We do not yet have the luxury of the cheat option yet, however we can abuse the fact that the function which reads the name of
the horse stops reading characters once it sees a 0xFF byte. Knowing this, the ASLR bits of these heap allocations can be leaked as follows:

```
for i in range(8):
┊   add_horse(i, 256, b'i' * 256)
┊   remove_horse(i)
┊   add_horse(i, 256, b'\xFF')
race()

p.recvuntil(b'WINNER: ')
aslr = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f'aslr: {hex(aslr)}')

remove_horse(0)
remove_horse(1)
```

NOTE: I'm allocating all the horses I will need for the entire exploit at this point which is why I'm allocating 8 specifically.
Additionally, I'm using the largest allocation size possible (256) to give myself as much room to send my ROP chain as I can. Plus,
we need at least five to race anyway, but I'm mainly just thinking ahead.

Output:

![image](https://user-images.githubusercontent.com/96510931/228078681-50ce3b47-af23-4406-9c13-41f49c6836b0.png)

Looks promising, so I'll elaborate on why this worked. In the for loop, I start by allocating a horse which does a malloc. Immediately
afterwards I free this horse, which puts heap metadata where the allocation once was. Since there was nothing in the tcache prior to
making this allocation, the ASLR bits are just XORed with zero, meaning the saved next pointer is just the ASLR bits. Adding another
horse again and sending nothing but an 0xFF byte as the name leaves the contents of the next pointer, which contains the ASLR bits, alone
and also gets rid of this entry from the tcache, allowing the same exact thing to happen in the next iteration of the for loop. 

So, when any of these horses win, the pointer to their name, which points to the next pointer which contains the ASLR bits, is 
printed after the word WINNER. It is also important that these horses are allocated, because if they are not they do not count in the race (recall
how remove_horse sets the pointer to zero, and that horses only participate in the racee if their respective pointer is non-zero).

Lastly, I'm removing horses 0 and 1 in preperation for what I am about to do next...

### Leaking LIBC

Now we get to be a dirty cheater and get away with it. An address in LIBC can be leaked, and the base address of LIBC can be calculated
as follows:

```
for i in range(8):
┊   add_horse(i, 256, b'i' * 256)
┊   remove_horse(i)
┊   add_horse(i, 256, b'\xFF')
race()

p.recvuntil(b'WINNER: ')
aslr = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f'aslr: {hex(aslr)}')

remove_horse(0)
remove_horse(1)
```

Output:

![image](https://user-images.githubusercontent.com/96510931/228084473-a2ddb978-16b9-46f7-92ac-864a0e7f2108.png)

Looks promising once again, but there is a bit of luck involved. TODO

