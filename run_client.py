import os
import platform
import subprocess
import signal
import sys
import random

def signal_handler(sig, frame):
    print("\n[INFO] Ctrl+C detected. Ending server script...")
    sys.exit(0)

def ensure_directories():
    """Ensure required directories exist"""
    directories = ["keys", "config", "bin/linux", "bin/windows", "bin/macos"]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def compile_client():
    ensure_directories()  # Crear directorios antes de compilar

    system = platform.system()
    if system == "Linux":
        bin_dir = "bin/linux"
        binary = os.path.join(bin_dir, "client")
    elif system == "Windows":
        bin_dir = "bin/windows"
        binary = os.path.join(bin_dir, "client.exe")
    elif system == "Darwin":  # macOS
        bin_dir = "bin/macos"
        binary = os.path.join(bin_dir, "client")
    else:
        print("Operative system is not supported.")
        return

    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    compile_cmd = ""
    if system == "Linux":
        compile_cmd = f"g++ src/client/client.cc src/client/socket_client.cc src/encryption/data_encryp.cc src/utils/hash_utils.cc src/utils/convert_data.cc -Iasio/include -pthread -lsodium -o {binary}"
    elif system == "Windows":
        compile_cmd = f"g++ src/client/client.cc src/client/socket_client.cc src/encryption/data_encryp.cc src/utils/hash_utils.cc src/utils/convert_data.cc -Iasio/include -o {binary}"
    elif system == "Darwin":  # macOS
        compile_cmd = f"g++ src/client/client.cc src/client/socket_client.cc src/encryption/data_encryp.cc src/utils/hash_utils.cc src/utils/convert_data.cc -o {binary} -std=c++17 -I/opt/homebrew/include -L/opt/homebrew/lib -lsodium"

    print(f"Compiling: {compile_cmd}")
    subprocess.run(compile_cmd, shell=True, check=True)

    print(f"Client compiled in {binary}")

def run_client():
    system = platform.system()
    if system == "Linux":
        bin_path = "bin/linux/client"
    elif system == "Windows":
        bin_path = "bin/windows/client.exe"
    elif system == "Darwin":  # macOS
        bin_path = "bin/macos/client"
    else:
        print("Operative system is not supported.")
        return

    if not os.path.exists(bin_path):
        print("The binary was not found. Run the compilation first")
        return

    print(f"Running client: {bin_path}")
    
    # Generar device ID automático si no se especifica
    default_id = f"device_{random.randint(1000, 9999)}"
    device_id = input(f"Enter device ID (or press Enter for '{default_id}'): ").strip()
    if not device_id:
        device_id = default_id
    
    print(f"Starting client with device ID: {device_id}")
    print("Note: Each client will have unique keys and register automatically")
    
    # Pasar device_id como argumento al programa C++
    subprocess.run([bin_path, device_id])

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    option = input("Do you want to compile the client? (y/n) ").lower()
    if option == 'y':
        compile_client()
    elif option != 'n':
        print("Invalid option, bye :(")
        exit(1)

    run_client()
