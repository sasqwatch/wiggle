import subprocess


# TODO: use ctypes to invoke SecCodeCheckValidity
def apple(filename):
    args = ['codesign', '-R=anchor apple', '-v', filename]
    status = subprocess.call(args, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return status == 0


def codesign(filename):
    args = ['codesign', '-dvvv', filename]
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT).decode('utf8')
    except Exception as e:
        return ''


if __name__ == "__main__":
    print(apple('/bin/sh'))
    print(apple('/etc/passwd'))
    print(codesign('/bin/sh'))
    print(codesign('/etc/passwd'))