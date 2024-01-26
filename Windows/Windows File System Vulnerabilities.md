## Alternate Data Streams
![](</Images/Pasted image 20231206192456.png>)


To hide exe in resource stream
`type <executable> > <file_name>:<hidden payload>`

Above command moves actual executable into filename

Can try running via `start <file_name:payload>`

This might not work so can be done with symlink

`mlink <filename:payload>`

