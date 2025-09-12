# GCC_reverse
solution que j'ai trouvé pour le CTFd GCC : All is in 

# prémisse :
d'abord pour get des infos j'ai fais : 
```bash
file AllIsIn.exe 
AllIsIn.exe: PE32+ executable (console) x86-64, for MS Windows
strings AllIsIn.exe 
```
ce qui me permet d'en savoir un peu plus sur le fichier et sur les string qu'il possède

# phase de reverse
ensuite j'ai ouvert Ghidra pour chercher d'ou venait le code qui permet d'entrer un mot de passe. J'ai donc fais : 
Search -> Decompiled text -> password
ce qui m'a permis de trouver le code qui permet la vefif de password
après lecture du code j'ai trouver que : 

* le mot de passe devait faire 38 caractères
* il était comparé à une ressource (stringtable) chargée via LoadStringA(hInstance, 0x65)
* donc il get la ressources 0x65 = 101 de la stringtable
* chaque caractère du mot de passe devait être égal au caractère de la ressource +5 en ASCII

Pour voir la ressource (stringtable #101), j’ai utilisé la commande :
```bash
strings -el ./AllIsIn.exe | less
```
L’option -el :
* -e sert à indiquer l’encodage des chaînes à extraire
* l = little-endian UTF-16 (Windows utilise souvent UTF-16LE pour stocker les chaînes dans les ressources).

ce qui donne :
&=UC>OAvK.Za,g.nZc/q.Zn+Zh/itZa./opm.nx (un peu de chance c'est le seul dans la table stringtable a être en litle-endian

# phase final
Comme le code faisait input[i] == resource[i] + 5, il fallait simplement ajouter +5 à chaque caractère de la ressource.
```python
s = "&=UC>OAvK.Za,g.nZc/q.Zn+Zh/itZa./opm.nx"
flag = "".join(chr(ord(c) + 5) for c in s)
print(flag)
```
BZHCTF{LeFLAG}
