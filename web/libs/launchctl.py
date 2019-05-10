import subprocess
import os


def get_files():
    files = set()
    proc = subprocess.Popen(['launchctl', 'dumpstate'], stdout=subprocess.PIPE)

    while True:
        line = proc.stdout.readline()
        if not line:
            break

        line = line.decode('utf8').strip()
        if not ' = ' in line:
            continue

        key, value = line.split(' = ', 1)
        if key == 'program':
            if os.path.islink(value):
                files.add(os.readlink(value))
            else:
                files.add(value)

    return files


if __name__ == '__main__':
    print(list(get_files()))