# Waybackurls with Python

Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for `*.domain` and output them on stdout.

## Basic Usage

### Single Domain

``` sh
python script.py example.com
```

### Multiple Domains (via stdin)

``` sh
cat domains.txt | python main.py
```
or

``` sh
echo "example.com" | python main.py
```

## Credit

forked from [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)
This tool was inspired by @mhmdiaa's [waybackurls.py](https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050) script.
Thanks to them for the great idea!
