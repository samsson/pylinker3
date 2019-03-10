# pylinker3

This is a python code for parsing and modifying microsoft .lnk files.

## Usage

usage:
```
python3 pylinker3.py [-h] -f file [-c cmdline] [--hide [HIDE]]
```

-h, --help                show this help message and exit

-f file, --file file      Input .lnk file to parse or modify

-c cmdline, --cmdline     optional: Set a new cmdline for the .lnk file

--hide [HIDE]             optional: Will hide the commandline from plain view if observed from explorer

-o output, --output       optional: Define output file. Default is inputfilename[0-9].lnk


Modifying a commandline will create a new copy of the file with modified commandline


example usage:
```
py pylinker3.py --file cmd.lnk -c '/c "powershell.exe calc"' --hide -o powershellcalc.lnk
```

To call pylinker3 from other file, this returns the results in a list.

```
import pylinker3
print(pylinker3.parse("cmd.lnk"))
```

### Prerequisites

You need python 3, tested on windows Python 3.7.2


## Authors

* **Sami Ruohonen** https://twitter.com/samiruohonen

## Acknowledgments

This tool is based on https://github.com/HarmJ0y/pylnker/blob/master/pylnker.py by HarmJ0y

Which is ported to python from: https://code.google.com/p/revealertoolkit/source/browse/trunk/tools/lnk-parse-1.0.pl
   Windows LNK file parser - Jacob Cunningham - jakec76@users.sourceforge.net

Microsoft documentation used as a reference:
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
