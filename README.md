# angry-birds

![alt text](https://github.com/Ethan-Blesch/AngrY-Birds/blob/main/images/table.png?raw=true "Logo Title Text 1")
angry-birds is an extension for angr-management which can map out user-writable sections of memory to help with exploit dev and reverse engineering. 


## Installation

Clone the repository:
```
git clone https://github.com/Ethan-Blesch/AngrY-Birds
```

Then from angr-management, click `Plugins`, `Manage Plugins`, then `Load plugin`, and navigate to the cloned directory. Select the `plugin.toml` file in your AngrY-Birds installation directory, and click through the rest of the load plugin dialogue. 

## Usage
After installation, there should now be an option labeled "Scan memory writes" under the `Plugins` menu. Click on this to launch the main AngrY-Birds window, and click the scan button. This should give you a list of memory writes that have a symbolic component, and ones with red highlights have met some heuristic criteria to be considered "suspicious" and are worth looking into.  

## Limitations and known bugs

- **Usability on larger programs:** AngrY-Birds has only really been tested on tiny little C programs that I wrote and compiled on my personal machine to test a specific kind of memory error, and even though I plan to work on this issue, in its current state, the tool will be slow and/or buggy on anything bigger than an average CTF challenge.
- **Memory writes through library functions:** Because of the way the tool is written, functions like `memcpy` and `strcpy` that perform buffer operations and have significant potential for memory errors each need to be implemented manually, and currently, `memcpy` is the only one that's sort of implemented, although it's a bit broken at the moment (read: doesn't work at all)
- **Other types of binaries or libraries:** AngrY-Birds is completely untested on anything other than a non-stripped C binary, for linux, using GCC and the standard C library, and while I'd love to explore ways to make AngrY-Birds function in a much broader scope, I've got a ton of other stuff going on and can't gurantee that this project is going to be maintained and expanded once I get it to a usable state that i'm happy with
- **GUI shenanigans:** There's several things with the GUI that are a bit fucky, and this is the first time I've ever done any GUI design, so please cut me some slack

##  Credits:
Programming: mistertoenails

Help with Angr: zardus

Emotional support: programmer_user, automatic, and mathlegend_175
