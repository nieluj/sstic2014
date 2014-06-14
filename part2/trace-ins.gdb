file badbios2.bin
target remote 127.1:1234

break *0x40285C
commands
silent
printf "-> calling sub_%8.8x (index = %d), x0 = 0x%8.8x, arg_48 = 0x%8.8x\n", $x2, *($x29 + 0x5c), $x0, $x1
cont
end

cont
