import os
import time
import subprocess
import zipfile
import datetime
import pandas as pd
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# --- CONFIGURACIÓN GLOBAL ---
HOSTNAME = os.environ.get('COMPUTERNAME', 'UnknownHost')
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = f"EVIDENCE_{HOSTNAME}_{TIMESTAMP}"
EVIDENCE_BAG_NAME = f"EvidenceBag_{HOSTNAME}_{TIMESTAMP}.zip"
TEMP_PASSWORD = "IncidentResponsePassword123" 
TIMELINE_DATA = []

# --- BANNER Y ARTE ASCII ---
BANNER = f"""
{Fore.CYAN}
         _   _       _   _    _
        /_\ | | __ _| |_| |_| |_ ___  _ __
       / _ \| |/ _` | __| __| __/ _ \| '__|
      / ___ \ | (_| | |_| |_| |_| (_) | |
     /_/   \_\_|\__,_|\__|\__|\__\___/|_|
               Forensics Triage Tool
{Style.RESET_ALL}
{Fore.YELLOW}  >> Analizando: {HOSTNAME} @ {TIMESTAMP}{Style.RESET_ALL}
"""

# --- FUNCIONES NÚCLEO ---

def create_output_directory():
    """Crea la carpeta temporal para guardar la evidencia."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"{Fore.GREEN}[+] Directorio de Evidencia Creado: {OUTPUT_DIR}{Style.RESET_ALL}")
    return OUTPUT_DIR

def run_system_command(command, filename, description):
    """Ejecuta un comando de sistema y guarda la salida."""
    try:
        print(f"{Fore.CYAN}[...]{Style.RESET_ALL} Recolectando: {description}")
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )

        output_path = os.path.join(OUTPUT_DIR, filename)
        
        with open(output_path, "w", encoding='utf-8') as f:
            f.write(f"--- COMANDO: {command} ---\n\n")
            f.write(result.stdout)
            
        global TIMELINE_DATA
        TIMELINE_DATA.append({
            'Timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Source': 'SystemCmd',
            'Event': description,
            'Details': f"Output saved to {filename}"
        })
            
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Guardado: {filename}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[!] ERROR al recolectar {filename}: {e}{Style.RESET_ALL}")
        return False

# --- FASES FORENSES ---

def phase_1_triage():
    """Recolección de Artefactos Críticos (Procesos, Conexiones)."""
    print(f"\n{Fore.MAGENTA}--- FASE 1: RECOLECCIÓN DE TRIAGE ---{Style.RESET_ALL}")
    
    if os.name == 'nt':
        run_system_command("tasklist /svc", "active_processes.txt", "Lista de Procesos Activos (Windows)")
        run_system_command("netstat -ano", "network_connections.txt", "Conexiones de Red Abiertas (netstat)")
    else: 
        run_system_command("ps aux", "active_processes.txt", "Lista de Procesos Activos (Linux)")
        run_system_command("ss -tuln", "network_connections.txt", "Conexiones de Red Abiertas (ss)")

    with open(os.path.join(OUTPUT_DIR, "recent_files_sim.txt"), "w") as f:
        f.write("Simulación de Archivos Abiertos Recientes:\nC:\\Users\\User\\Documents\\secret_plans.docx\nC:\\Temp\\malware_loader.exe")
    TIMELINE_DATA.append({
        'Timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Source': 'FileSys',
        'Event': 'Archivos Recientes',
        'Details': 'Simulación de artefactos LNK'
    })
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Simulación de Archivos Recientes Guardada.")


def phase_1_5_registry_triage():
    """Análisis de Persistencia en el Registro de Windows (Usa REG QUERY)."""
    print(f"\n{Fore.MAGENTA}--- FASE 1.5: ANÁLISIS DE PERSISTENCIA (Registro) ---{Style.RESET_ALL}")
    
    if os.name != 'nt':
        print(f"{Fore.YELLOW}[!] Saltando: La lectura del Registro (Windows) no aplica en este OS.{Style.RESET_ALL}")
        return
        
    registry_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    
    output_path = os.path.join(OUTPUT_DIR, "registry_persistence.txt")
    
    try:
        with open(output_path, "w", encoding='utf-8') as f:
            f.write("--- ANÁLISIS DE PERSISTENCIA (REG QUERY) ---\n")
            for key in registry_keys:
                f.write(f"\n[ CLAVE: {key} ]\n")
                
                result = subprocess.run(
                    f"reg query {key}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5
                )
                
                if result.returncode != 0:
                    f.write(f"ERROR/VACÍO: No se pudo acceder o la clave está vacía.\n")
                else:
                    f.write(result.stdout)
                
        global TIMELINE_DATA
        TIMELINE_DATA.append({
            'Timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Source': 'Registry',
            'Event': 'Análisis de Claves Run (Persistencia)',
            'Details': f"Output saved to registry_persistence.txt"
        })
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Claves de Persistencia del Registro analizadas y guardadas.")
            
    except Exception as e:
        print(f"{Fore.RED}[!] ERROR fatal al leer el Registro: {e}{Style.RESET_ALL}")


def phase_2_timeline():
    """Generación del Timeline Forense Consolidado."""
    print(f"\n{Fore.MAGENTA}--- FASE 2: CONSTRUCCIÓN DEL TIMELINE ---{Style.RESET_ALL}")

    if not TIMELINE_DATA:
        print(f"{Fore.YELLOW}[!] No hay datos para el Timeline. Saltando esta fase.{Style.RESET_ALL}")
        return

    df_timeline = pd.DataFrame(TIMELINE_DATA)
    df_timeline['Timestamp'] = pd.to_datetime(df_timeline['Timestamp'])
    df_timeline = df_timeline.sort_values(by='Timestamp')
    
    timeline_path = os.path.join(OUTPUT_DIR, "forensic_timeline.csv")
    df_timeline.to_csv(timeline_path, index=False)
    
    print(f"{Fore.GREEN}[+] Timeline Forense Consolidado Generado y Guardado en: forensic_timeline.csv{Style.RESET_ALL}")
    print(df_timeline.to_string())


def phase_3_packaging():
    """Empaquetado y Encriptación (Simulada) de la Evidencia (Evidence Bag)."""
    print(f"\n{Fore.MAGENTA}--- FASE 3: EMPAQUETADO DE EVIDENCIA ---{Style.RESET_ALL}")
    
    try:
        with zipfile.ZipFile(EVIDENCE_BAG_NAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(OUTPUT_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, OUTPUT_DIR))

        print(f"{Fore.GREEN}[+] Archivo de Evidencia (Evidence Bag) Creado: {EVIDENCE_BAG_NAME}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] IMPORTANTE: La evidencia está protegida (simulada). Contraseña: {TEMP_PASSWORD}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] ERROR al crear el Evidence Bag: {e}{Style.RESET_ALL}")

# --- FUNCIÓN PRINCIPAL ---

def main():
    print(BANNER)
    
    create_output_directory()
    
    phase_1_triage()
    
    phase_1_5_registry_triage()
    
    phase_2_timeline()
    
    phase_3_packaging()
    
    print(f"\n{Fore.MAGENTA}*** AUTOSPY-BOT: ANÁLISIS COMPLETO ***{Style.RESET_ALL}")
    print(f"{Fore.BLUE}La evidencia está lista para su análisis fuera del sistema comprometido.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()