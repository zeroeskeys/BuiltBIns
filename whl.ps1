Get-ChildItem *.whl | ForEach-Object { 
    $zip = $_.FullName
    $dest = "C:\Users\Public\Downloads\python-3.11.0-embed-amd64\Lib\site-packages"
    Expand-Archive -Path $zip -DestinationPath $dest -Force
}
