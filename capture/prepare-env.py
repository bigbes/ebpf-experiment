import re
import typing
import os.path
import subprocess
import http.client

from urllib.parse import urlparse


def uname() -> str:
    """Execute uname -r to get the Linux kernel version."""
    process = subprocess.Popen(["uname", "-r"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, _ = process.communicate()
    return stdout.decode().strip()


def download_file(url, local_filename):
    """Download a file from a given URL to a local filename"""
    # Parse the URL to extract the hostname and path
    url_parsed = urlparse(url)
    hostname = url_parsed.netloc
    path = url_parsed.path

    # Create a connection to the host
    connection = http.client.HTTPSConnection(hostname)
    connection.request("GET", path)

    # Get the response
    response = connection.getresponse()
    if response.status == 200:
        # Write the file
        with open(local_filename, 'wb') as file:
            file.write(response.read())
    else:
        print(f"Failed to download file: HTTP \
              {response.status} {response.reason}")

    # Close the connection
    connection.close()


# 4.15.0-211-generic
class LinuxKernelVersion:
    def __init__(self, version_string=None):
        if version_string is None:
            version_string = uname()

        self.version_string = version_string
        self.major = 0
        self.minor = 0
        self.patch = 0
        self.extended = 0
        self.extra = ''
        self.parse_version()

    def parse_version(self):
        # Regular expression to match the Linux kernel version pattern
        pattern = r'^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:-([\w\d.-]+))?$'
        match = re.match(pattern, self.version_string)
        if match:
            self.major = int(match.group(1))
            self.minor = int(match.group(2))
            self.patch = int(match.group(3))
            self.patch = int(match.group(4)) if match.group(4) else 0
            self.extra = match.group(5) if match.group(5) else ''
        else:
            raise ValueError("Invalid Linux kernel version format: '" +
                             self.version_string + "'")

    def wsl(self) -> bool:
        return "WSL2" in self.extra

    def github_branch(self):
        if self.wsl():
            return "linux-msft-wsl-" + self.version_string.split("-")[0]
        else:
            return "v"+self.major+"."+self.minor

    def __str__(self):
        return f"Version: {self.version_string}, Major: {self.major}, \
            Minor: {self.minor}, Patch: {self.patch}, Extra: {self.extra}"

    def __eq__(self, other):
        return (self.major, self.minor, self.patch, self.extra) == \
            (other.major, other.minor, other.patch, other.extra)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return (self.major, self.minor, self.patch, self.extra) < \
            (other.major, other.minor, other.patch, other.extra)

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other):
        return not self.__le__(other)

    def __ge__(self, other):
        return not self.__lt__(other)


def get_os() -> typing.List[str]:
    process = subprocess.Popen(["lsb_release", "--id", "--release", "-s"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, _ = process.communicate()
    name: str = stdout.decode().strip()
    return name.split()


github_kernel = "https://raw.githubusercontent.com/torvalds/linux/%s/%s"
github_wsl_kernel = "https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/%s/%s" # noqa


def obtain_kernel_pathname(version: LinuxKernelVersion, path):
    if version.wsl():
        return github_wsl_kernel % (version.github_branch(), path)
    else:
        return github_kernel % (version.github_branch(), path)


def download_files_from_kernel(version: LinuxKernelVersion,
                               download_to: str = None):

    print("Downloading kernel files from {version.version_string}")

    for filename in [
            "tools/lib/bpf/bpf_endian.h",
            # "tools/lib/bpf/bpf_helper_defs.h",
            "tools/lib/bpf/bpf_helpers.h",
            "tools/lib/bpf/bpf_tracing.h",
    ]:
        remote = obtain_kernel_pathname(version, filename)
        local = os.path.basename(filename)
        print("downloading file from " + remote + " to " + local)
        download_file(remote, local)


github_libbpf = "https://raw.githubusercontent.com/libbpf/libbpf/%s/%s"


def obtain_libbpf_pathname(version: str, filename: str = None):
    return github_libbpf % (version, filename)


def download_files_from_libbpf(version: str = None, download_to: str = None):
    if version is None:
        version = "v1.4.0"

    print(f"Downloading libbpf files from {version}")

    for filename in [
            "src/bpf_endian.h",
            "src/bpf_helper_defs.h",
            "src/bpf_helpers.h",
            "src/bpf_tracing.h",
    ]:
        remote = obtain_libbpf_pathname(version, filename)
        local = os.path.join(download_to, os.path.basename(filename))
        print(f"downloading file from {remote} to {local}")
        download_file(remote, local)


def version_check() -> LinuxKernelVersion:
    min_ver = LinuxKernelVersion("5.5.0-generic")

    ver = LinuxKernelVersion()
    if min_ver > ver:
        raise RuntimeError(f"expected linux version to be at least v5.5, got \
                           {ver.version_string} on {get_os()}")
    return min_ver


def generate_vmlinux(download_to: str = None):
    print("Generating vmlinux.h")
    with open(os.path.join(download_to, "vmlinux.h"), "w") as file:
        cmd = ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
               "format", "c"]
        process = subprocess.Popen(cmd,
                                   stdout=file,
                                   stderr=subprocess.PIPE)
        _, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Failed to generate vmlinux.h: {stderr.decode()}")
            return


if __name__ == "__main__":
    output = "ebpf/include"

    ver = version_check()
    # download_files_from_kernel(ver)
    download_files_from_libbpf("v0.6.1", output)
    generate_vmlinux(output)
