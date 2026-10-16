from .admesh import Admesh
from .alsalib import AlsaLib
from .antiword import Antiword
from .asn1c import Asn1c
from .avro import Avro
from .boost import Boost
from .brotli import Brotli
from .bzip2 import Bzip2
from .c_icap import Cicap
from .cityhash import Cityhash
from .clickhouse import Clickhouse
from .clickhouse_cpp import ClickhouseCPPChecker
from .cppkafka import Cppkafka
from .cpp_ipc import CppIpc
from .curl import Curl
from .dpdk import Dpdk
from .duktape import Duktape
from .dxflib import Dxflib
from .elasticlient import Elasticlient
from .ffmpeg import FFmpeg
from .flatbuffers import Flatbuffers
from .fmt import Fmt
from .grpc import Grpc
from .highwayhash import Highwayhash
from .hpgl2gcode import Hpgl2gcode
from .hyperscan import Hyperscan
from .ipp_crypto import CryptographyPrimitives
from .jemalloc import Jemalloc
from .libarchive import Libarchive
from .libcgroup import Libcgroup
from .libconfig import LibConfig
from .libharu import Libharu
from .libhtp import Libhtp
from .libinjection import Libinjection
from .libjpeg_turbo import LibjpegTurbo
from .libjson import Libjson
from .libogg import Libogg
from .libpcap import Libpcap
from .libredwg import Libredwg
from .libsl3 import Libsl3
from .libsoundio import Libsoundio
from .libsrtp import Libsrtp
from .libuemf import Libuemf
from .libuv import Libuv
from .libvorbis import Libvorbis
from .libwebsockets import Libwebsockets
from .libxcb import Libxcb
from .libxkbcommon import Libxkbcommon
from .libxml2 import Libxml2
from .libxslt import Libxslt
from .libzmq import Libzmq
from .lua import Lua
from .lz4 import Lz4
from .mbedtls import Mbedtls
from .mimalloc import Mimalloc
from .minhook import MinHook
from .minitrace import Minitrace
from .miniz import Miniz
from .mongoose import Mongoose
from .msgpack import Msgpack
from .musl import Musl
from .ndpi import Ndpi
from .nghttp2 import Nghttp2
from .nginx import Nginx
from .onetbb import OneTBB
from .opencv import OpenCV
from .openexr import Openexr
from .openssl import Openssl
from .openvino import Openvino
from .otris import Otris
from .pmmact import Pmacct
from .poco import Poco
from .poppler import Poppler
from .prometheus_cpp import PrometheusCpp
from .protobuf import Protobuf
from .ragel import Ragel
from .rapidjson import Rapidjson
from .re2 import Re2
from .recoll import Recoll
from .samba import Samba
from .smtpclient import SmtpClient
from .spdlog import Spdlog
from .sqlite import Sqlite
from .suricata import Suricata
from .tac_plus import TacPlus
from .tesseract import Tesseract
from .toml import Toml
from .uchardet import Uchardet
from .userver import Userver
from .vmime import Vmime
from .winfile import Winfile
from .xapian_core import XapianCore
from .xxhash import XXhash
from .zlib import Zlib
from .zstd import Zstd

ALL_CHECKERS = [
    Admesh(),
    AlsaLib(),
    Antiword(),
    Asn1c(),
    Avro(),
    Boost(),
    Brotli(),
    Bzip2(),
    Cicap(),
    Cityhash(),
    Clickhouse(),
    ClickhouseCPPChecker(),
    Cppkafka(),
    CppIpc(),
    CryptographyPrimitives(),
    Curl(),
    Dpdk(),
    Duktape(),
    Dxflib(),
    Elasticlient(),
    FFmpeg(),
    Flatbuffers(),
    Fmt(),
    Grpc(),
    Highwayhash(),
    Hpgl2gcode(),
    Hyperscan(),
    Jemalloc(),
    Libarchive(),
    Libcgroup(),
    LibConfig(),
    Libharu(),
    Libhtp(),
    Libinjection(),
    LibjpegTurbo(),
    Libjson(),
    Libogg(),
    Libpcap(),
    Libredwg(),
    Libsl3(),
    Libsoundio(),
    Libsrtp(),
    Libuemf(),
    Libuv(),
    Libvorbis(),
    Libwebsockets(),
    Libxcb(),
    Libxkbcommon(),
    Libxml2(),
    Libxslt(),
    Libzmq(),
    Lua(),
    Lz4(),
    Mbedtls(),
    Mimalloc(),
    MinHook(),
    Minitrace(),
    Miniz(),
    Mongoose(),
    Msgpack(),
    Musl(),
    Ndpi(),
    Nghttp2(),
    Nginx(),
    OneTBB(),
    OpenCV(),
    Openexr(),
    Openssl(),
    Openvino(),
    Otris(),
    Pmacct(),
    Poco(),
    Poppler(),
    PrometheusCpp(),
    Protobuf(),
    Ragel(),
    Rapidjson(),
    Re2(),
    Recoll(),
    Samba(),
    SmtpClient(),
    Spdlog(),
    Sqlite(),
    Suricata(),
    TacPlus(),
    Tesseract(),
    Toml(),
    Uchardet(),
    Userver(),
    Vmime(),
    Winfile(),
    XapianCore(),
    XXhash(),
    Zlib(),
    Zstd(),
]
