## PDF
#peepdf can be used to get malicious code from pdfs. Usage.
#create script
```echo 'extract js > javascript-from-demo_notsuspicious.pdf' > extracted_javascript.txt```
run script with peepdf using script from above and the file being inspectioned
```peepdf -s extracted_javascript.txt notsuspicious.pdf```

## MS Office Macros
#vmonkey is used here. usage is simple. 
```vmonkey <filename>```

## Memory Dumps
#volatility this will output a processes list for for further examination
```volatility -f Win7-Jigsaw.raw imageinfo```
once pid is found you can analyze dll's with
```volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 dlllist -p 3704```





