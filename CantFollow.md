# Write-up CantFollow

## Introduction

Le challenge CantFollow consiste à trouver un mot de passe de 0x2b (43 caractères).  
Le binaire utilise `fork()` et `ptrace()` pour effectuer la vérification via un processus enfant, ce qui rend l'analyse dynamique classique (avec GDB par exemple) impossible (en tout cas moi j'ai pas réussis sans Ghidra!).  

Le binaire est stripé (pas de symboles) mais les sections `.data` contiennent les valeurs de ce qui nous intéressera plus tard!

---

## Analyse du code

### Fonction principale

le processus parent :

```c
undefined8 FUN_00101298(void)
{
    uint __pid;
    byte local_55;
    byte local_48[56];

    printf("Password: ");
    fgets((char *)local_48, 0x2c, stdin);
    if (strlen((char *)local_48) == 0x2b) { // 43 caractères
        __pid = fork();
        if (__pid == 0) {
            FUN_00101229(); // Processus enfant
        }
        ptrace(PTRACE_ATTACH, __pid, 0, 0);
        ptrace(PTRACE_CONT, __pid, 0, 0);
        waitpid(__pid, 0, 0);

        for (local_55 = 0; local_55 < 0x2b; local_55++) {
            ptrace(PTRACE_POKEDATA, __pid, &DAT_001041e0, local_48[local_55]);
            ptrace(PTRACE_CONT, __pid, 0, 0);
            waitpid(__pid, 0, 0);

            uint val = ptrace(PTRACE_PEEKDATA, __pid, &DAT_001041e0, 0);
            DAT_001041e0 = val & 0xffffffff;

            if ((&DWORD_00104060)[local_55] != DAT_001041e0 ||
                ((&BYTE_00104020)[local_55] & local_48[local_55]) != (&DWORD_00104120)[local_55]) {
                puts("Failure...");
                return 1;
            }
        }

        printf("Success ! %s is your flag.\n", local_48);
        return 0;
    }

    puts("Failure...");
    return 0;
}
```

le processus enfant :

```c
void FUN_00101229(void)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    DAT_001041e0 = DAT_001041e0 * ((&BYTE_00104020)[DAT_001041e8] ^ DAT_001041e0);
    swi(3); // point d'arrêt
}
```
Le processus enfant prend un octet de password[i] et le transforme via la formule :
```c
child_res = password[i] * (password[i] ^ child_arr[i])
```

Puis le parent vérifie deux condition :
* child_res == result_arr_1[i]
* (password[i] & child_arr[i]) == result_arr_2[i]


### Données extraites du binaire

avec Ghidra on peut extraire les donnée et on trouve : 
```python
#  pour calculer la transform = BYTE_00104020
child_arr = bytearray.fromhex(
    "1313e185239b20f32493f6febe1bcd28207cb50a574f9bc47e87dab68e519ca62e71de016763ca9e07da6b00"
)

# result_arr_1 = DWORD_00104060 (uint32 little-endian)
result_arr_1_hex = bytearray.fromhex(
    "E2140000AA190000882F0000D23300000C2700006E3C0000B92B00006C280000A52D00002C62000020250000"
    "A0260000285500003C190000702F0000C9040000901A0000FD0C00002E5A0000980C0000BE150000F0050000"
    "4C6C0000C02D00003F0C000018610000FB2C000008520000A7250000320500009D620000201C0000801B0000"
    "44020000984C0000300900007610000044160000884400007F210000500A00006B500000BE0A000000000000"
)

# result_arr_2 = DWORD_00104120 (uint32 little-endian)
result_arr_2_hex = bytearray.fromhex(
    "02000000120000004000000001000000000000000200000020000000300000000400000003000000300000003"
    "0000000240000001B0000000000000020000000200000005C0000003500000000000000510000004F00000010"
    "000000000000005E000000000000001000000024000000020000005100000000000000200000002E0000007000"
    "00005200000000000021000000430000004200000010000000000000005200000069000000"
)
```

### pipeline de brute force

* On regarde un octet du mot de passe à la fois. (password[i])
* Pour cet octet, on essaie toutes les valeurs de 0 à 255.
* On applique les deux conditions :
* password[i] * (password[i] ^ child_arr[i]) == result_arr_1[i]
* (password[i] & child_arr[i]) == result_arr_2[i]
* Dès qu’une valeur satisfait les deux conditions, on l’accepte comme le caractère correct à cette position.
* On passe à l’octet suivant.


### Script de res

```python
# Conversion des résultats en uint32 little-endian
result_arr_1 = [int.from_bytes(result_arr_1_hex[i*4:(i*4)+4], byteorder="little") for i in range(44)]
result_arr_2 = [int.from_bytes(result_arr_2_hex[i*4:(i*4)+4], byteorder="little") for i in range(44)]

# Bruteforce du flag
flag = bytearray(44)

for i in range(44):
    for j in range(256):
        tmp_val = j * (j ^ child_arr[i])
        tmp_target = result_arr_1[i]
        tmp_cmp = result_arr_2[i]
        
        if tmp_val == tmp_target and (child_arr[i] & j) == tmp_cmp:
            flag[i] = j
            print(f"Position {i}: {chr(j)}")
            break

print("\nFlag:", flag.decode())
```

Résume/conclusion : 
* Le binaire utilise un processus enfant pour calculer un child_res dépendant du mot de passe et d’une valeur dans .data.
* Le parent vérifie ensuite deux conditions pour chaque octet du mot de passe.
* La solution consiste à bruteforcer chaque octet indépendamment, car chaque octet a seulement 256 possibilités et les conditions sont simples.





