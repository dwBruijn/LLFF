import distro

IS_UBUNTU = distro.linux_distribution()[0].startswith('Ubuntu')
VT_APIKEY = ""