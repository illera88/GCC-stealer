# Google Chrome Cookies Stealer (GCC-Stealer)
This tools aims to be a statically compiled binary that can decrypt the Chrome family browsers (Chrome, Brave and Chromium) cookies.

At the moment it works on Windows and Linux.

## Usage
The tool must be run **in the same** system that the target browser is. Chrome uses a key derived from each system to encrypt the cookies so it's mandatory that the tool gets run on the same system to proceed to the correct cookies decryption.

```
Usage: GCC-stealer.exe [options]

Google Chrome Cookie Stealer (GCC-Stealer)

Optional arguments:
-h --help       shows help message and exits [default: false]
-v --version    prints version information and exits [default: false]
--json-print    print a JSON structure with the decrypted cookies you can import in Cookie-Editor [default: false]
--json-file     create a JSON file with the decrypted cookies you can import in Cookie-Editor [default: "cookies.json"]
--cookies-out   path where to write decrypted cookies DB to [default: "Cookies_decrypted"]
--cookies-path  tell GCC-Stealer where to look for the cookies DB

It must be run on the same system you want to decrypt the cookies from
```


## Compilation
The project uses Github Actions as CI to build the tool. Check the action files to see compile instructions. 


