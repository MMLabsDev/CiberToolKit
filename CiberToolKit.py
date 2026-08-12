#importar librerías------------------------------------------------------
import socket
import os
import requests
import random
import string
from rich.console import Console
from rich.panel import Panel

#definir funciones-------------------------------------------------------
def limpiar():
    os.system("cls")

def menu():
    print("""
╔══════════════════════════════════════╗
║          CiberToolKit                ║
║      Cybersecurity Toolkit           ║
╠══════════════════════════════════════╣
║  [1] Information Gathering           ║
║  [2] Encoding / Decoding             ║
║  [3] Hash Tools                      ║
║  [4] Network Utilities               ║
║  [5] Exit                            ║
╚══════════════════════════════════════╝""")
#sistema principal-------------------------------------------------------    
console = Console()

console.print(
    Panel.fit(
        "[bold bright_green]current version[/]",
        border_style="bright_green",
        title="[ M.M.Labs.Dev ]",
        subtitle="v1.0"
    )
)

while True:
    limpiar()
    menu()
    usuario = int(input("select function: "))

    if usuario == 1:
        print("""
╔════════════════════════════════════╗
║      INFORMATION GATHERING         ║
╠════════════════════════════════════╣
║ [1] IP Lookup                      ║
║ [2] DNS Lookup                     ║
║ [3] Whois Lookup                   ║
║ [4] Port Scanner                   ║
║ [5] HTTP Headers                   ║
║ [6] Subdomain Finder               ║
║ [7] Back                           ║
╚════════════════════════════════════╝""")

        selection = int(input("select function: "))

        if selection == 1:
            url = input("URL: ")

            try:
                respuesta = requests.get(url)

                for clave, valor in respuesta.headers.items():
                    print(f"{clave}: {valor}")

            except:
                print("❌ No se pudo encontrar la URL")

        elif selection == 2:
            dominio = input("Dominio: ")

            try:
                ip = socket.gethostbyname(dominio)
                print(f"La IP es: {ip}")

            except socket.gaierror:
                print("❌ No se pudo encontrar ese dominio.")

        elif usuario == "5":
            break
