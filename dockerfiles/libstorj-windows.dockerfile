FROM microsoft/nanoserver
MAINTAINER Storj Labs (bill@storj.io)
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"]

ADD https://raw.githubusercontent.com/computeronix/libstorj/master/dockerfiles/get_dep_ver.ps1 get_dep_ver.ps1
ADD https://raw.githubusercontent.com/computeronix/libstorj/master/dockerfiles/dst-root-ca-x3.cer dst-root-ca-x3.cer

RUN .\get_dep_ver.ps1; \
    Invoke-WebRequest $('https://github.com/Storj/libstorj/releases/download/v{0}/libstorj-{0}-win64.zip' -f $env:LIBSTORJ_VERSION) -OutFile 'libstorj.zip' -UseBasicParsing; \
    Expand-Archive libstorj.zip -DestinationPath C:\ ; \
    Copy-Item "$('.\libstorj-{0}\bin\storj.exe' -f $env:LIBSTORJ_VERSION)"  "$('{0}\System32\' -f $env:WINDIR)"; \
    Remove-Item -Path libstorj.zip; \
    Remove-Item "$('.\libstorj-{0}' -f $env:LIBSTORJ_VERSION)" -recurse; \
    \
    Import-Certificate -FilePath "dst-root-ca-x3.cer" -CertStoreLocation 'Cert:\LocalMachine\Root' -Verbose ; \
    Remove-Item -Path dst-root-ca-x3.cer; \
    \
    Write-Host storj --version; storj --version; \
    Write-Host storj get-info; storj get-info;

CMD [""]
ENTRYPOINT ["powershell"]
