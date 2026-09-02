# ============================================================
# CiberToolKit - M.M.Labs.Dev
# Cybersecurity Toolkit
# Version 1.0
# ============================================================

# Importar librerías
import socket
import os
import requests
import hashlib
import base64
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ============================================================
# Configuración
# ============================================================

console = Console()

# ============================================================
# Funciones generales
# ============================================================

def limpiar():
    """Limpia la consola."""
    os.system("cls" if os.name == "nt" else "clear")


def pausar():
    """Pausa el programa."""
    input("\nPresiona ENTER para continuar...")


def pedir_opcion(mensaje):
    """Solicita una opción numérica evitando errores de entrada."""
    while True:
        try:
            return int(input(mensaje))
        except ValueError:
            console.print(
                "[bold red]❌ Introduce un número válido.[/]"
            )


def menu():
    """Menú principal."""
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
╚══════════════════════════════════════╝
""")


# ============================================================
# INFORMATION GATHERING
# ============================================================

def menu_information():
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
╚════════════════════════════════════╝
""")


def ip_lookup():
    """Obtiene la IP de un dominio."""
    dominio = input("Dominio o URL: ").strip()

    # Quitamos protocolos para evitar errores
    dominio = (
        dominio
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    try:
        ip = socket.gethostbyname(dominio)

        console.print(
            f"\n[bold bright_green]✔ IP encontrada:[/] {ip}"
        )

    except socket.gaierror:
        console.print(
            "[bold red]❌ No se pudo resolver el dominio.[/]"
        )


def dns_lookup():
    """Obtiene información DNS básica."""
    dominio = input("Dominio: ").strip()

    try:
        informacion = socket.getaddrinfo(dominio, None)

        ips = set()

        for resultado in informacion:
            ip = resultado[4][0]
            ips.add(ip)

        console.print("\n[bold cyan]Direcciones encontradas:[/]")

        for ip in ips:
            print(f"  → {ip}")

    except socket.gaierror:
        console.print(
            "[bold red]❌ No se pudo resolver ese dominio.[/]"
        )


def whois_lookup():
    """
    Consulta Whois mediante el servicio público de RDAP.
    RDAP es una alternativa moderna a Whois.
    """
    dominio = input("Dominio: ").strip()

    try:
        respuesta = requests.get(
            f"https://rdap.org/domain/{dominio}",
            timeout=10
        )

        if respuesta.status_code == 200:
            datos = respuesta.json()

            print("\n========== RDAP ==========")

            print(f"Dominio: {datos.get('ldhName', 'N/A')}")
            print(f"Handle: {datos.get('handle', 'N/A')}")

            estado = datos.get("status", [])

            if estado:
                print("Estado:")
                for item in estado:
                    print(f"  → {item}")

        else:
            console.print(
                "[bold red]❌ No se encontró información RDAP.[/]"
            )

    except requests.RequestException:
        console.print(
            "[bold red]❌ Error al consultar RDAP.[/]"
        )


def port_scanner():
    """
    Escáner básico de puertos TCP.
    Utilízalo únicamente contra sistemas autorizados.
    """

    host = input("Host autorizado: ").strip()

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        console.print(
            "[bold red]❌ No se pudo resolver el host.[/]"
        )
        return

    print(f"\nIP objetivo: {ip}")

    try:
        inicio = int(input("Puerto inicial: "))
        final = int(input("Puerto final: "))

        if inicio < 1 or final > 65535 or inicio > final:
            console.print(
                "[bold red]❌ Rango de puertos inválido.[/]"
            )
            return

    except ValueError:
        console.print(
            "[bold red]❌ Debes introducir números.[/]"
        )
        return

    print("\nEscaneando...\n")

    encontrados = 0

    for puerto in range(inicio, final + 1):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(0.3)

        resultado = sock.connect_ex((ip, puerto))

        if resultado == 0:
            console.print(
                f"[bold green]✔ Puerto {puerto} abierto[/]"
            )
            encontrados += 1

        sock.close()

    if encontrados == 0:
        console.print(
            "\n[yellow]No se encontraron puertos abiertos.[/]"
        )


def http_headers():
    """Obtiene las cabeceras HTTP de una URL."""

    url = input("URL: ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        respuesta = requests.get(
            url,
            timeout=10
        )

        print("\n========== HTTP HEADERS ==========\n")

        for clave, valor in respuesta.headers.items():
            print(f"{clave}: {valor}")

    except requests.RequestException:
        console.print(
            "[bold red]❌ No se pudo conectar con la URL.[/]"
        )


def subdomain_finder():
    """
    Busca subdominios comunes mediante DNS.
    Utilízalo únicamente en dominios autorizados.
    """

    dominio = input("Dominio autorizado: ").strip()

    subdominios = [
        "www",
        "mail",
        "ftp",
        "dev",
        "test",
        "api",
        "admin",
        "blog",
        "shop",
        "portal"
    ]

    encontrados = 0

    print("\nBuscando subdominios...\n")

    for sub in subdominios:

        objetivo = f"{sub}.{dominio}"

        try:
            ip = socket.gethostbyname(objetivo)

            console.print(
                f"[green]✔ {objetivo}[/] → {ip}"
            )

            encontrados += 1

        except socket.gaierror:
            pass

    if encontrados == 0:
        console.print(
            "[yellow]No se encontraron subdominios en la lista básica.[/]"
        )


# ============================================================
# ENCODING / DECODING
# ============================================================

def encoding_menu():

    print("""
╔════════════════════════════════════╗
║       ENCODING / DECODING          ║
╠════════════════════════════════════╣
║ [1] Base64 Encode                  ║
║ [2] Base64 Decode                  ║
║ [3] URL Encode                     ║
║ [4] URL Decode                     ║
║ [5] Back                           ║
╚════════════════════════════════════╝
""")


def base64_encode():

    texto = input("Texto: ")

    resultado = base64.b64encode(
        texto.encode("utf-8")
    ).decode("utf-8")

    print(f"\nResultado: {resultado}")


def base64_decode():

    texto = input("Base64: ")

    try:
        resultado = base64.b64decode(
            texto
        ).decode("utf-8")

        print(f"\nResultado: {resultado}")

    except Exception:
        console.print(
            "[bold red]❌ Base64 inválido.[/]"
        )


def url_encode():

    from urllib.parse import quote

    texto = input("Texto: ")

    resultado = quote(texto)

    print(f"\nResultado: {resultado}")


def url_decode():

    from urllib.parse import unquote

    texto = input("URL encoded: ")

    resultado = unquote(texto)

    print(f"\nResultado: {resultado}")


# ============================================================
# HASH TOOLS
# ============================================================

def hash_menu():

    print("""
╔════════════════════════════════════╗
║            HASH TOOLS              ║
╠════════════════════════════════════╣
║ [1] MD5                            ║
║ [2] SHA-1                          ║
║ [3] SHA-256                        ║
║ [4] SHA-512                        ║
║ [5] Back                           ║
╚════════════════════════════════════╝
""")


def generar_hash(algoritmo):

    texto = input("Texto: ").encode("utf-8")

    if algoritmo == "md5":
        resultado = hashlib.md5(texto).hexdigest()

    elif algoritmo == "sha1":
        resultado = hashlib.sha1(texto).hexdigest()

    elif algoritmo == "sha256":
        resultado = hashlib.sha256(texto).hexdigest()

    elif algoritmo == "sha512":
        resultado = hashlib.sha512(texto).hexdigest()

    else:
        return

    print(f"\nHash {algoritmo.upper()}:")
    print(resultado)


# ============================================================
# NETWORK UTILITIES
# ============================================================

def network_menu():

    print("""
╔════════════════════════════════════╗
║        NETWORK UTILITIES           ║
╠════════════════════════════════════╣
║ [1] My Local Hostname              ║
║ [2] My Local IP                    ║
║ [3] Resolve Host                   ║
║ [4] Back                           ║
╚════════════════════════════════════╝
""")


def hostname():

    nombre = socket.gethostname()

    print(f"\nHostname: {nombre}")


def local_ip():

    try:
        nombre = socket.gethostname()
        ip = socket.gethostbyname(nombre)

        print(f"\nIP local: {ip}")

    except socket.gaierror:
        console.print(
            "[bold red]❌ No se pudo obtener la IP.[/]"
        )


def resolve_host():

    host = input("Host: ").strip()

    try:
        ip = socket.gethostbyname(host)

        print(f"\n{host} → {ip}")

    except socket.gaierror:
        console.print(
            "[bold red]❌ No se pudo resolver el host.[/]"
        )


# ============================================================
# MENÚS SECUNDARIOS
# ============================================================

def information_gathering():

    while True:

        limpiar()
        menu_information()

        opcion = pedir_opcion("select function: ")

        if opcion == 1:
            ip_lookup()

        elif opcion == 2:
            dns_lookup()

        elif opcion == 3:
            whois_lookup()

        elif opcion == 4:
            port_scanner()

        elif opcion == 5:
            http_headers()

        elif opcion == 6:
            subdomain_finder()

        elif opcion == 7:
            break

        else:
            console.print(
                "[bold red]❌ Opción inválida.[/]"
            )

        if opcion != 7:
            pausar()


def encoding_decoding():

    while True:

        limpiar()
        encoding_menu()

        opcion = pedir_opcion("select function: ")

        if opcion == 1:
            base64_encode()

        elif opcion == 2:
            base64_decode()

        elif opcion == 3:
            url_encode()

        elif opcion == 4:
            url_decode()

        elif opcion == 5:
            break

        else:
            console.print(
                "[bold red]❌ Opción inválida.[/]"
            )

        if opcion != 5:
            pausar()


def hash_tools():

    while True:

        limpiar()
        hash_menu()

        opcion = pedir_opcion("select function: ")

        if opcion == 1:
            generar_hash("md5")

        elif opcion == 2:
            generar_hash("sha1")

        elif opcion == 3:
            generar_hash("sha256")

        elif opcion == 4:
            generar_hash("sha512")

        elif opcion == 5:
            break

        else:
            console.print(
                "[bold red]❌ Opción inválida.[/]"
            )

        if opcion != 5:
            pausar()


def network_utilities():

    while True:

        limpiar()
        network_menu()

        opcion = pedir_opcion("select function: ")

        if opcion == 1:
            hostname()

        elif opcion == 2:
            local_ip()

        elif opcion == 3:
            resolve_host()

        elif opcion == 4:
            break

        else:
            console.print(
                "[bold red]❌ Opción inválida.[/]"

            )

        if opcion != 4:
            pausar()


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

def main():

    while True:

        limpiar()

        console.print(
            Panel.fit(
                "[bold bright_green]CiberToolKit[/]\n"
                "[dim]Cybersecurity Toolkit[/]\n\n"
                "[bold]Current version: v1.0[/]",
                border_style="bright_green",
                title="[ M.M.Labs.Dev ]",
                subtitle="v1.0"
            )
        )

        menu()

        usuario = pedir_opcion("select function: ")

        if usuario == 1:
            information_gathering()

        elif usuario == 2:
            encoding_decoding()

        elif usuario == 3:
            hash_tools()

        elif usuario == 4:
            network_utilities()

        elif usuario == 5:

            limpiar()

            console.print(
                Panel.fit(
                    "[bold bright_green]"
                    "Gracias por usar CiberToolKit"
                    "[/]\n\n"
                    "[dim]M.M.Labs.Dev[/]",
                    border_style="bright_green"
                )
            )

            break

        else:

            console.print(
                "[bold red]❌ Opción inválida.[/]"
            )

            pausar()


# ============================================================
# Ejecutar programa
# ============================================================

if __name__ == "__main__":
    main()
