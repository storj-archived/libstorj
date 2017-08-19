$uri = 'https://github.com/Storj/libstorj/releases/latest'
$site = invoke-webrequest $uri -DisableKeepAlive -UseBasicParsing

$found=0
$site.Links | Foreach {
    $url_items = $_.href
    if($url_items -like "*-win64.zip" -and $found -ne 1) {
        $filename=$url_items
        $found=1
    }
}

if($found -ne 1) {
    Write-Host "Unable to gather Libstorj Version";
}

$url="${url}$filename"
$version = $filename.Substring(0,$filename.Length-"-win64.zip".Length)
$pos = $version.IndexOf("storj-")
$version = $version.Substring($pos+6)

Write-Host "Found Latest Version of Libstorj - ${version}"
$env:LIBSTORJ_VERSION = "${version}"
