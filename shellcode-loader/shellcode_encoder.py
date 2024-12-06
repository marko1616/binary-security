def xor_string(shellcode:bytes, key_string:bytes) -> bytes:
    result = b''
    key_length = len(key_string)

    for i, char in enumerate(shellcode):
        result += (char ^ key_string[i % key_length]).to_bytes()

    return result

shellcode = b'\xeb\xfe'
key_string = b"C:\\Windows\\system32"

xor_result = xor_string(shellcode, key_string)
print(xor_result)
print("unsigned char shellcode[] = {")
for byte in xor_result:
    print(f"{hex(byte)},",end="")
print()
print("};")

