package=gmp
$(package)_version=6.1.2
$(package)_download_path=https://ftp.gnu.org/gnu/gmp/gmp-$($(package)_version).tar.bz2
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=5275bb04f4863a13516b2f39392ac5e272f5e1bb8057b18aec1c9b79d73d8fb2

#default settings
$(package)_config_env_default=
$(package)_config_opts_default=

# arm specific settings
$(package)_config_opts_arm=--disable-assembly
$(package)_config_opts_aarch64-linux-gnu=$($(package)_config_opts_arm)
$(package)_config_opts_arm-linux-gnueabihf=$($(package)_config_opts_arm)

# set settings based on host
$(package)_config_env = $(if $($(package)_config_env_$(HOST)), $($(package)_config_env_$(HOST)), $($(package)_config_env_default))
$(package)_config_opts = $(if $($(package)_config_opts_$(HOST)), $($(package)_config_opts_$(HOST)), $($(package)_config_opts_default))
