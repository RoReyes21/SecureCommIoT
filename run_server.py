import os
import platform
import subprocess
import signal
import sys

def signal_handler(sig, frame):
    print("\n[INFO] Ctrl+C detected. Ending server script...")
    sys.exit(0)

def compile_server():
    system = platform.system()
    bin_dir = "bin/linux" if system == "Linux" else "bin/windows"
    binary = os.path.join(bin_dir, "server" if system == "Linux" else "server.exe")

    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    compile_cmd = ""
    if system == "Linux":
        compile_cmd = f"g++ src/appserver/server.cc -Iasio/include -pthread -o {binary}"
    elif system == "Windows":
        compile_cmd = f"g++ src/appserver/server.cc -Iasio/include -o {binary}"
    else:
        print("Operative system is not supported.")
        return

    print(f"Compiling: {compile_cmd}")
    subprocess.run(compile_cmd, shell=True, check=True)

    print(f"Server compiled in {binary}")

def run_server():
    system = platform.system()
    bin_path = "bin/linux/server" if system == "Linux" else "bin/windows/server.exe"

    if not os.path.exists(bin_path):
        print("The binary was not found. Run the compilation first")
        return

    print(f"Running server: {bin_path}")
    subprocess.run(bin_path, shell=True)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    option = input("Do you want to compile the server? (y/n) ").lower()
    if option == 'y':
        compile_server()
    elif option != 'n':
        print("Invalid option, bye :(")
        exit(1)

    run_server()
