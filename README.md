## Synopsis

The script will dynamically identify your current domain + any existing trusts, validate the passed AD group exists 
in your current domain, and then enumerate AD memebers of User, Group, or Computer object classes.  The details 
are pulled from the discovered AD object's home domain which can provide more detail than the default Get-ADGroupMember cmdlet.  
Further customization of the -Property parameter inside Get-ADObjectDetails is possible.  The final objects contain
a custom 'DomainName' attribute that can be used for further filtering if needed.

## Usage

1) Clone to local repository
2) Start Powershell
3) Run Get-Help C:\pathTo\Get-ADGroupMemberEnhanced.ps1 -Full

## License

BSD 2-Clause License

Copyright (c) 2017, https://infiniteloop.io
All rights reserved.

