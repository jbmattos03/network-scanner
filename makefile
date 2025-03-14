# Compilador
CC = gcc

# Flags de compilação
CFLAGS = -Wall -Wextra -O2 -Iinclude

# Arquivos fonte
SOURCES = src/scanner.c src/main.c src/utils.c

# Arquivos objeto
OBJECTS = $(SOURCES:.c=.o)

# Nome do executável
EXECUTABLE = main

# Regra de compilação
all: $(SOURCES) $(EXECUTABLE)

# Regra para construir o executável
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

# Regra para construir os objetos
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

# Regra para limpar os arquivos
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

# Regra para rodar o programa
run:
	./$(EXECUTABLE) $(ARGS)

# Phony targets
.PHONY: all clean run