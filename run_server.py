import os
import platform
import subprocess
import signal
import sys

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

def compile_server():
    ensure_directories()  # Crear directorios antes de compilar

    system = platform.system()
    if system == "Linux":
        bin_dir = "bin/linux"
        binary = os.path.join(bin_dir, "server")
    elif system == "Windows":
        bin_dir = "bin/windows"
        binary = os.path.join(bin_dir, "server.exe")
    elif system == "Darwin":  # macOS
        bin_dir = "bin/macos"
        binary = os.path.join(bin_dir, "server")
    else:
        print("Operative system is not supported.")
        return

    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    compile_cmd = ""
    if system == "Linux":
        compile_cmd = f"g++ src/appserver/server.cc src/utils/convert_data.cc src/utils/hash_utils.cc src/encryption/data_encryp.cc -Iasio/include -lsodium -pthread -o {binary}"
    elif system == "Windows":
        compile_cmd = f"g++ src/appserver/server.cc src/utils/convert_data.cc src/utils/hash_utils.cc src/encryption/data_encryp.cc -Iasio/include -o {binary}"
    elif system == "Darwin":  # macOS
        compile_cmd = f"g++ src/appserver/server.cc src/utils/convert_data.cc src/utils/hash_utils.cc src/encryption/data_encryp.cc -o {binary} -std=c++17 -I/opt/homebrew/include -L/opt/homebrew/lib -lsodium"
    else:
        print("Operative system is not supported.")
        return
    print(f"Compiling: {compile_cmd}")
    subprocess.run(compile_cmd, shell=True, check=True)

    print(f"Server compiled in {binary}")

def run_server():
    system = platform.system()
    if system == "Linux":
        bin_path = "bin/linux/server"
    elif system == "Windows":
        bin_path = "bin/windows/server.exe"
    elif system == "Darwin":  # macOS
        bin_path = "bin/macos/server"
    else:
        print("Operative system is not supported.")
        return

    if not os.path.exists(bin_path):
        print("The binary was not found. Run the compilation first")
        return

    print(f"Running server: {bin_path}")
    subprocess.run([f"./{bin_path}"], shell=False)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    option = input("Do you want to compile the server? (y/n) ").lower()
    if option == 'y':
        compile_server()
    elif option != 'n':
        print("Invalid option, bye :(")
        exit(1)

    run_server()
