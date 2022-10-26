# User interface header

  ▄████  ▒█████   ▄▄▄     ▄▄▄█████▓▄▄▄█████▓▄▄▄█████▓
 ██▒ ▀█▒▒██▒  ██▒▒████▄   ▓  ██▒ ▓▒▓  ██▒ ▓▒▓  ██▒ ▓▒
▒██░▄▄▄░▒██░  ██▒▒██  ▀█▄ ▒ ▓██░ ▒░▒ ▓██░ ▒░▒ ▓██░ ▒░
░▓█  ██▓▒██   ██░░██▄▄▄▄██░ ▓██▓ ░ ░ ▓██▓ ░ ░ ▓██▓ ░ 
░▒▓███▀▒░ ████▓▒░ ▓█   ▓██▒ ▒██▒ ░   ▒██▒ ░   ▒██▒ ░ 
 ░▒   ▒ ░ ▒░▒░▒░  ▒▒   ▓▒█░ ▒ ░░     ▒ ░░     ▒ ░░   
  ░   ░   ░ ▒ ▒░   ▒   ▒▒ ░   ░        ░        ░    
░ ░   ░ ░ ░ ░ ▒    ░   ▒    ░        ░        ░      
      ░     ░ ░        ░  ░                          
                                                     

print("\n****************************************************************")
print("\n* License : MIT                                                *")
print("\n* Copyright (c) 2022 RR Lubin                              	*")
print("\n* https://www.debug.tips                                  		*")
print("\n*                           									*")
print("\n****************************************************************")

# Contributer: RR Lubin	
# Author: Josh Stroschein
# Date: 04 October 2022
# Resources:  
#   Writeup: https://debug.tips/question/how-can-i-write-static-xor-deobfuscation-string-in-python-script/
#	Documentation: https://hex-rays.com/products/ida/support/idapython_docs/
#   Sample: https://app.any.run/tasks/8823560f-d44a-45bc-9706-aac3ac7dd30c/

# This plugin serves to deobfuscate strings with Ida Pro; 
# via menu, File, you may import script file: De-Ida.py, 
# achieving expedient print-outs of decrypted string(s), 
# any errors will display in 'Output window'.

# Spawn point [is logic = brain]  
any errors   
def get_string(addr, size):
# defined function called after entry point 
  out = ""
  for offset in range(addr, (addr + size)):
      out += chr(Byte(offset))
      # Take address; and address + size (size of key & encoded data), 
      # read the location in memory from that pointer and convert it 
      # to 'byte' and 'char' ultimately concatenating into a string
      # Define: range -- with address and address + size, so take that address and add whatever number of bytes
  return out
 
def decrypt(key,cipher,size):
# defined function called after entry point
  decrypted_string = ""
  cnt = 0
  for cnt in range(0,size):
    decrypted_string = decrypted_string + chr(ord(cipher[cnt]) ^ ord(key[cnt  % len(key)]))
    # Concatenate to string; one character at a time,
    # using Python Ord() function to return Unicode code from a given character.
    # 'chr' cipher is based on count ('cnt'); key is based on index, count mod, length of that key.
    # Ord() ensures both are numeric values, which is parsed with Bitwise XOR. 
    # Resultant output is converted to character ('chr') allowing concatenation into string.
  return str(decrypted_string)

# Entry point [is action = body] -- 
print "[*] Attempting to decrypt strings in malware... "
for x in XrefsTo(0x10001210, flags=0):
# Use of De-Ida.py script require replacing '0x10001210' with your own reference address. 
# Take function: XrefsTo -- using Ida's Python API: https://github.com/idapython/src
# give it an address (i.e. 0x10001210); then iterate: for x -- over each one of those cross references. 

  addr = idc.PrevHead(x.frm)
  obfuscated_string = GetOperandValue(addr, 0)
  # Those iterated cross-reference(s) provide an output: addr (address)
  # Take function: idc.PrevHead -- pass newly defined 'x' [via crossreference.fromproperty]
  # Instructing De-Ida.py to print an address; the very same, previous, to the referenced function call.
  # This grants access to prior assembly Instruction, its operands, and futher prodding.
  # Feed the newly defined adress output: addr into 'GetOperandValue'
  # The obtained operand is 'obfuscated_string'

  addr = idc.PrevHead(addr)
  # Again, take function: idc.PrevHead -- pass the recent 'addr' [from above] to get a brand new address.
  key = GetOperandValue(addr,0)
  # The obtained address is 'key'

  addr = idc.PrevHead(addr)
  size = GetOperandValue(addr,0)
  # Again, for size, take function: idc.PrevHead -- pass the recent 'addr' [from key] to get another address.

  print "Addr: 0x%x  | Key: 0x%x | Cipher: 0x%x | Size: %d" %  (x.frm,key, obfuscated_string, size)
  # Print statements assist in debugging, confirming results match expectations.
  
  decrypted_string = decrypt(get_string(obfuscated_string, size), get_string(key, size),size)
  # Take function: decrypt -- pass the key, cipher, and encoded text.
  # Results equal decrypted_string: a string to store De-Ida.py's decrypted response(s)
  print "Decrypted: %s" % (decrypted_string)

  MakeComm(idc.NextHead(idc.NextHead(x.frm)), "[*] " + decrypted_string)
  # Make Comment
  # Define the address of comment, define what is that comment.
