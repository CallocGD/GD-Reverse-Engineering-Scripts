<a href="https://discord.gg/C3VjpJqCFe"><img src=https://img.shields.io/badge/Discord_Server-3670a0?style=for-the-badge&logo=discord&logoColor=white></a>
</p>


# GD-Reverse-Engineering-Scripts
This is where I am putting my new tools I make comapred to the old repo this tool will implement newer and smarter techniques to decompiling the game faster.
As someone who has a partime job elsewhere, playing catchup with robtop's updates has been quite the hassle which means I have to switch gears as there isn't
anybody who is currently actively trying to do what I am doing (as of 11-25-2024) this means that yes, me learning java is now a requirement.



# TODOs
- [X] Dump All Virtuals, Dumps libcocos2d along with the other virtuals that are robtop's class objects... (Luckily All I had to do was modify Mat's script)

- [ ] Fix floats and other signatures script. In arm32-v7 floats get assigned as s0+ instead of `r0-r3` and then `Stack[0x0]` and so on... This script plans to fix that as well as take all
function comments and edit all those functions into ghidra.

- [ ] find all `std::basic_string` functions, this script aims to find all the std::basic_string functions and write all the signatures in correctly. This one has a higher difficulty
      then the __Fix floats and other signatures script__ .

- [ ] One or two tutorials on how to use DumpAllVirtuals.java and make_vtables3.py to send vtables to Ghidra android decompilation

- [ ] Function to C++ Converter (Kinda Wishful thinking) this would cleanup maybe some of the std::string slop and CCPoint slop, fixing `CCDirector::getWinSize() inline shit` and try and turn everything into valid C++ code for you to copy+paste. 

