# Rotation

## What we're given

We are provided with just a text file with an encrypted flag:

```
xqkwKBN{z0bib1wv_l3kzgxb3l_25l7k61j}
```

Seeing as the curly braces and underscores are still there and look like they might not have been encrypted, and also considering the name of the challenge, they are likely just doing a character rotation for the letters to encrypt it. 

## Scripting

Considering what the decrypted flag should look like, we can use the actual ascii values to calculate the difference, in other words how much to rotate by.

The script is pretty straight forward. The key for the 'decrypt' function below can be calculated as I described up above. This function just does a circular rotation by 'key' amount for each letter, ignoring all other weird ascii values. I'm ignoring numbers for now and hoping it just works out.

```
def decrypt(ciphertext, key):
┊   plaintext = ''
┊   for char in ciphertext:
┊   ┊   if char.isalpha():
┊   ┊   ┊   char_code = ord(char)
┊   ┊   ┊   rotated_code = (char_code - key - 65) % 26 + 65 \
┊   ┊   ┊   ┊   ┊   if char.isupper() else (char_code - key - 97) % 26 + 97
┊   ┊   ┊   plaintext += chr(rotated_code)
┊   ┊   else:
┊   ┊   ┊   plaintext += char
┊   return plaintext

encrypted = ''
with open('rotation.txt', 'r') as file:
┊   encrypted = file.read().replace('\n', '')

# 0x70 is an ascii 'p' which should be the first character of the flag
difference = int(encrypted.encode()[0]) - 0x70
print(decrypt(encrypted, difference))
```

## Output

Looking at the result, it appears we did not need to do anything with the numbers:

![image](https://user-images.githubusercontent.com/96510931/229057067-a26ac071-5468-4626-9858-148a9bd9aec7.png)

