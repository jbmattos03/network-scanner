# network-scanner
Implementação de um network scanner simples em C.

# Modo de uso
```
make run ARGS="[OPTIONS]"
```

# Features
## 1. Network scanning
### Modo de uso

```
make run ARGS=" -n [OPTIONS]"
```

Ou:

```
make run ARGS=" --network [OPTIONS]"
```

#### Opções
1. Prefixo de rede (CIPR)
2. -s: Inserir um endereço IP inicial
3. -e: Inserir um endereço IP final
4. -t: Definir um timeout (segundos)

## 2. Port scanning
### Modo de uso
```
make run ARGS=" -p [OPTIONS]"
```

Ou:

```
make run ARGS=" --ports [OPTIONS]"
```

#### Opções
1. Range de portas ("x-y")
2. -i: Definir um ip para ser o alvo
3. -t: Definir um timeout (segundos)