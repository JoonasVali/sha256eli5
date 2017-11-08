# SHA256ELI5
Simple debuggable SHA256 implementation for learning purposes where the whole hash creation is
done in binary Strings instead of byte arrays.

# WHY?
Sha256 is a popular hashing algorithm, but I found it quite difficult to understand as all existing
implementations were performance optimized and used bitwise operations on bytes and byte arrays.
This essentially resulted the algorithms being obfuscated by complexity of operations.
If you, like me, find this hard to follow, then sha256ELI5 is for you:

```java
words[j] |= ((block[j * 4 + m] & 0x000000FF) << (24 - m * 8));
```

So I figured the best way to learn something is to reinvent it.
SHA256ELI5, where ELI5 means 'Explain Like I'm Five', is designed to run operations in String arrays
for easy following of the program flow once you connect the debugger.

# LICENSE (UNLICENSED)

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>

