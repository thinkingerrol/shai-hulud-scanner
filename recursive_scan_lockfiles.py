import os
import sys
import subprocess


def find_directories_with_package_lock(root_dir, max_depth=2):
    """
    Recursively find subdirectories containing package-lock.json,
    skipping any node_modules directories, limited by max_depth.
    """
    result = []

    def recurse(current_dir, depth):
        if depth > max_depth:
            return

        try:
            entries = os.listdir(current_dir)
        except PermissionError:
            return

        if "package-lock.json" in entries:
            result.append(current_dir)

        for entry in entries:
            path = os.path.join(current_dir, entry)
            if os.path.isdir(path) and entry != "node_modules":
                recurse(path, depth + 1)

    recurse(root_dir, 0)
    return result


def process_directories(directories):
    """
    Run `python3 -m src.cli --dir <dir>` for each directory until one fails.
    """
    total = len(directories)
    for idx, d in enumerate(directories, start=1):
        print(f"[{idx}/{total}] Processing {d}...")
        result = subprocess.run([
            sys.executable, "-m", "src.cli", "--dir", d
        ])
        if result.returncode != 0:
            print(f"Command failed in {d} with exit code {result.returncode}")
            sys.exit(result.returncode)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <root_directory>")
        sys.exit(1)

    root_dir = sys.argv[1]

    if not os.path.isdir(root_dir):
        print(f"Error: {root_dir} is not a valid directory")
        sys.exit(1)

    directories = find_directories_with_package_lock(root_dir)

    if not directories:
        print("No directories with package-lock.json found.")
        return

    process_directories(directories)
    print("All directories processed successfully.")


if __name__ == "__main__":
    main()
