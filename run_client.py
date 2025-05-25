import os
import platform
import subprocess
import signal
import sys

def signal_handler(sig, frame):
    print("\n[INFO] Ctrl+C detected. Ending server script...")
    sys.exit(0)

def compile_client():
    system = platform.system()
    bin_dir = "bin/linux" if system == "Linux" else "bin/windows"
    binary = os.path.join(bin_dir, "client" if system == "Linux" else "client.exe")

    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    compile_cmd = ""
    if system == "Linux":
        compile_cmd = f"g++ src/client/client.cc -Iasio/include -pthread -o {binary}"
    elif system == "Windows":
        compile_cmd = f"g++ src/client/client.cc -Iasio/include -o {binary}"
    else:
        print("Operative system is not supported.")
        return

    print(f"Compiling: {compile_cmd}")
    subprocess.run(compile_cmd, shell=True, check=True)

    print(f"Client compiled in {binary}")

def run_client():
    system = platform.system()
    bin_path = "bin/linux/client" if system == "Linux" else "bin/windows/client.exe"

    if not os.path.exists(bin_path):
        print("The binary was not found. Run the compilation first")
        return

    print(f"Running client: {bin_path}")
    subprocess.run(bin_path, shell=True)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    choice = input("Do you want to compile the client? (y/n) ").lower()
    if choice == 'y':
        compile_client()
    elif option != 'n':
        print("Invalid option, bye :(")
        exit(1)

    run_client()
