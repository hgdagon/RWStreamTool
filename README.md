# RWStreamTool
Experimental tool to unpack Renderware stream files from the game Harry Potter and the Goblet of Fire

Usage:
```
./strtool.py <path/to/input/file_or_folder> [options]
options:
    -r  Recursive
    -b  Build
```

Can pack an unpack. Mainly intended for studying the format and content, so it dumps a lot of info.
Asset replacement not tested. May add a GUI in the future for viewing the assets (plain text files, string databases, fonts, textures), instead of dumping multiple JSONs.

References:

[Shape file strucure](https://rewiki.miraheze.org/wiki/EA_SSH_FSH_Image_(Type_1))

[Loc file structure](https://rewiki.miraheze.org/wiki/EA_Games_LOC)
